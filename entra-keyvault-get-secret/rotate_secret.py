# -*- coding: utf-8 -*-
"""定期轮换 Entra 应用的 client secret 并写入 Azure Key Vault（写入端）。

与同目录 get_secret.py（读取端）配合，互不修改:
  get_secret.py    : 应用运行时从 Key Vault 读最新 secret
  rotate_secret.py : 定期给 Entra 应用生成新 secret 并写入 Key Vault（本脚本）

流程: 换 Graph token -> 列现有密码 -> addPassword 生成新密码 -> 换 KV token
      -> PUT 写入 Key Vault -> removePassword 删旧密码 -> 更新 credential.ini

用法:
  python rotate_secret.py --check         # 只检查现有密码到期情况
  python rotate_secret.py --dry-run       # 只显示将做什么
  python rotate_secret.py                 # 执行完整轮换
  python rotate_secret.py --days 180      # 新密码有效期 180 天
  python rotate_secret.py --no-delete-old # 保留旧密码
  python rotate_secret.py --no-update     # 不写回 credential.ini

前置权限:
  - Graph: Application.ReadWrite.OwnedBy（且为应用 owner）或 Application.ReadWrite.All
  - Key Vault 写权限: Key Vault Secrets Officer 或访问策略 Secret 的 Set
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from configparser import ConfigParser
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

import requests

# 1) 配置（同名环境变量优先）
CONFIG = {
    "TENANT_ID": "280bf41d-bf29-4912-9f4a-42def550b467",
    "API_CLIENT_ID": "fdcdc6b6-f65c-44c3-a584-1891b0d8920f",
    "API_CLIENT_SECRET": "",
    "KEYVAULT_NAME": "keyvaultkenliang1126",
    "SECRET_NAME": "entra-oidc-client-secret",
    "KEYVAULT_SCOPE": "https://vault.azure.net/.default",
    "GRAPH_SCOPE": "https://graph.microsoft.com/.default",
    "API_VERSION": "7.4",
    "TARGET_APP_OBJECT_ID": "cec141da-2115-46b3-925d-31c4f7f66576",   # 要轮换的应用的"对象 ID"，不是 client id
    "TARGET_APP_CLIENT_ID": "",   # 可选，仅用于写 credential.ini
    "ROTATE_DAYS": "90",
    # 轮换后是否删除旧密码 true/false（命令行 --delete-old / --no-delete-old 可覆盖）
    "DELETE_OLD_SECRETS": "false",
}

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
CREDENTIAL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "credential.ini")


def _config(key: str) -> str:
    return os.environ.get(key, "").strip() or str(CONFIG.get(key, "")).strip()


def _safe_json(resp: requests.Response) -> dict[str, Any]:
    try:
        data = resp.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _decode_jwt(token: str) -> dict[str, Any]:
    """仅解码 JWT 的 payload 段（不验签），用于查看 aud/roles/scp。"""
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    segment = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(segment))
    except (ValueError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _mask(value: str) -> str:
    if not value:
        return "(空)"
    return value[:6] + "..." if len(value) > 9 else value


def _fmt_utc(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> datetime | None:
    if not value:
        return None
    if not value:
        return None
    try:
        # Graph 返回形如 2027-04-28T09:23:17.783Z，带毫秒
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        pass
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _days_left(end_dt: datetime | None) -> str:
    if not end_dt:
        return "未知"
    return f"{(end_dt - datetime.now(timezone.utc)).days} 天"


# 2) 换取 token（通用）
def get_token(scope: str) -> str:
    url = f"https://login.microsoftonline.com/{_config('TENANT_ID')}/oauth2/v2.0/token"
    body = urlencode({
        "grant_type": "client_credentials",
        "client_id": _config("API_CLIENT_ID"),
        "client_secret": _config("API_CLIENT_SECRET"),
        "scope": scope,
    })
    resp = requests.post(url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=30)
    data = _safe_json(resp)
    if resp.status_code != 200 or "access_token" not in data:
        err = data.get("error_description") or data.get("error") or resp.text
        raise SystemExit(f"换取 token 失败 (HTTP {resp.status_code}, scope={scope}): {err}")
    return data["access_token"]


# 3) Microsoft Graph: 列出/新增/删除 client secret
def graph_list_credentials(token: str, object_id: str) -> list[dict[str, Any]]:
    url = f"{GRAPH_BASE}/applications/{object_id}/passwordCredentials"
    resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=30)
    data = _safe_json(resp)
    if resp.status_code == 403:
        raise SystemExit(
            "Graph 403: 服务主体缺少权限。请授予 Microsoft Graph 的 "
            + "'Application.ReadWrite.OwnedBy'（且为应用 owner）或 'Application.ReadWrite.All'，并授予管理员同意。"
        )
    if resp.status_code == 404:
        raise SystemExit(f"Graph 404: 找不到应用 objectId '{object_id}'，请检查 TARGET_APP_OBJECT_ID。")
    if resp.status_code != 200:
        raise SystemExit(f"列出现有密码失败 (HTTP {resp.status_code}): {resp.text}")
    return data.get("value", []) or []


def graph_list_owners(token: str, object_id: str) -> list[dict[str, Any]]:
    url = f"{GRAPH_BASE}/applications/{object_id}/owners"
    resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=30)
    data = _safe_json(resp)
    if resp.status_code != 200:
        raise SystemExit(
            f"读取应用所有者失败 (HTTP {resp.status_code}): {resp.text}\n"
            + "（读取 owners 需 Application.Read.All 或 Directory.Read.All，可跳过此检查）"
        )
    return data.get("value", []) or []


def graph_add_password(token: str, object_id: str, display_name: str, end_dt: str) -> dict[str, Any]:
    url = f"{GRAPH_BASE}/applications/{object_id}/addPassword"
    payload = {"passwordCredential": {"displayName": display_name, "endDateTime": end_dt}}
    resp = requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"}, timeout=30)
    data = _safe_json(resp)
    if resp.status_code == 403:
        raise SystemExit(
            "Graph 403: 服务主体没有写应用密码的权限（能列出密码说明只有读权限）。\n"
            + "请到 Entra → 应用注册 → 你的服务主体应用 → API 权限：\n"
            + "  1) 添加 Microsoft Graph 的【应用程序权限】Application.ReadWrite.OwnedBy，\n"
            + "     并把该服务主体设为目标应用的【所有者】，否则仍会 403；\n"
            + "     或改用权限更大的 Application.ReadWrite.All（无需设 owner）；\n"
            + "  2) 点【代表 <租户> 授予管理员同意】，确认状态为已授予；\n"
            + "  3) 等 1~2 分钟权限生效后重跑。\n"
            + f"原始响应: {resp.text}"
        )
    if resp.status_code not in (200, 201):
        raise SystemExit(f"生成新密码失败 (HTTP {resp.status_code}): {resp.text}")
    if not data.get("secretText"):
        raise SystemExit(
            "响应里没有 secretText。请确认调用方拥有 Application.ReadWrite.OwnedBy 权限（该权限才返回明文）。"
        )
    return data


def graph_remove_password(token: str, object_id: str, key_id: str) -> None:
    url = f"{GRAPH_BASE}/applications/{object_id}/removePassword"
    resp = requests.post(url, json={"keyId": key_id}, headers={"Authorization": f"Bearer {token}"}, timeout=30)
    if resp.status_code not in (200, 204):
        raise SystemExit(f"删除旧密码 {key_id} 失败 (HTTP {resp.status_code}): {resp.text}")


# 4) Key Vault: 写入 secret（同名新建版本）
def kv_set_secret(token: str, secret_name: str, value: str, exp_seconds: int) -> dict[str, Any]:
    url = f"https://{_config('KEYVAULT_NAME')}.vault.azure.net/secrets/{secret_name}"
    payload: dict[str, Any] = {"value": value, "attributes": {"exp": exp_seconds}}
    resp = requests.put(
        url, params={"api-version": _config("API_VERSION")}, json=payload,
        headers={"Authorization": f"Bearer {token}"}, timeout=30,
    )
    data = _safe_json(resp)
    if resp.status_code == 401:
        raise SystemExit("Key Vault 401: token 无效/过期，或 scope 与云环境不匹配。")
    if resp.status_code == 403:
        raise SystemExit(
            "Key Vault 403: 服务主体没有写入 secret 的权限。请分配 RBAC 角色 "
            + "'Key Vault Secrets Officer'，或在访问策略勾选 Secret 的 'Set'。"
        )
    if resp.status_code not in (200, 201):
        raise SystemExit(f"写入 Key Vault 失败 (HTTP {resp.status_code}): {resp.text}")
    return data


# 5) 本地 credential.ini
def read_credential() -> dict[str, str]:
    parser = ConfigParser()
    if not os.path.exists(CREDENTIAL_FILE):
        return {}
    parser.read(CREDENTIAL_FILE, encoding="utf-8")
    if not parser.has_section("credential"):
        return {}
    return {
        "client_id": parser.get("credential", "client_id", fallback=""),
        "client_secret": parser.get("credential", "client_secret", fallback=""),
        "expiry_date": parser.get("credential", "expiry_date", fallback=""),
    }


def save_credential(client_id: str, client_secret: str, expiry_date: str) -> None:
    parser = ConfigParser()
    parser["credential"] = {
        "client_id": client_id,
        "client_secret": client_secret,
        "expiry_date": expiry_date,
    }
    with open(CREDENTIAL_FILE, "w", encoding="utf-8") as f:
        parser.write(f)


# 6) 主流程
def _debug_token() -> None:
    """解码 Graph access token，判断是 app-only(roles) 还是 delegated(scp)。"""
    claims = _decode_jwt(get_token(_config("GRAPH_SCOPE")))
    roles = claims.get("roles") or []
    print("Graph access token 解码结果:")
    print(f"  aud   : {claims.get('aud')}")
    print(f"  appid : {claims.get('appid')}")
    print(f"  roles : {roles}")
    print(f"  scp   : {claims.get('scp')}")
    if roles:
        print("  => app-only token，已带 application 权限(roles)，权限配置正确。")
    else:
        print("  !! 该 token 没有任何 roles，说明只配了 Delegated(委托) 权限。")
        print("     client_credentials 流只认【应用程序权限】，委托权限对它无效。")


def run(args: argparse.Namespace) -> None:
    if args.debug_token:
        _debug_token()
        return
    object_id = _config("TARGET_APP_OBJECT_ID")
    if not object_id:
        raise SystemExit("请先填写 TARGET_APP_OBJECT_ID（Entra 应用的 对象 ID，不是 client id）。")

    if args.check_owner:
        print(f"[check-owner] 列出应用 {object_id} 的所有者 ...")
        owners = graph_list_owners(get_token(_config("GRAPH_SCOPE")), object_id)
        me = _config("API_CLIENT_ID")
        for o in owners:
            print(f"  {o.get('displayName')}  appId={o.get('appId')}  objectId={o.get('id')}")
        if not owners:
            print("  没有任何所有者。")
        if any(o.get("appId") == me for o in owners):
            print(f"  => 服务主体 {me} 已是所有者，Application.ReadWrite.OwnedBy 前提满足。")
        else:
            print(f"  !! 服务主体 {me} 不在所有者列表，这就是 addPassword 返回 403 的原因。")
        return

    secret_name = _config("SECRET_NAME")
    rotate_days = int(args.days or _config("ROTATE_DAYS") or "90")
    # 是否删除旧密码：命令行显式开关优先，否则读 DELETE_OLD_SECRETS 配置
    delete_old = (
        args.delete_old
        if args.delete_old is not None
        else _config("DELETE_OLD_SECRETS").lower() in ("1", "true", "yes", "y", "on")
    )

    print(f"[步骤1] 换取 Microsoft Graph token (scope={_config('GRAPH_SCOPE')}) ...")
    graph_token = get_token(_config("GRAPH_SCOPE"))

    print("[步骤2] 列出现有 client secret ...")
    existing = graph_list_credentials(graph_token, object_id)
    if not existing:
        print("  当前应用没有任何 client secret。")
    for c in existing:
        end_dt = _parse_iso(c.get("endDateTime", ""))
        print(
            f"  keyId={c.get('keyId')}  displayName={c.get('displayName')}  "
            + f"过期={c.get('endDateTime')}  剩余={_days_left(end_dt)}"
        )
    old_key_ids = [c["keyId"] for c in existing if c.get("keyId")]

    if args.check:
        print("\n（--check：只检查，不做任何修改）")
        return

    start = datetime.now(timezone.utc)
    end = start + timedelta(days=rotate_days)
    display_name = args.display_name or f"rotated-{start.strftime('%Y%m%d')}"

    print(f"\n[步骤3] 生成新 client secret（{rotate_days} 天，到 {_fmt_utc(end)}）...")
    if args.dry_run:
        print(f"  (dry-run) addPassword: displayName={display_name}, endDateTime={_fmt_utc(end)}")
        if delete_old:
            print("  (dry-run) 将写入 Key Vault，并删除旧密码: " + (", ".join(old_key_ids) or "(无)"))
        else:
            print("  (dry-run) 将写入 Key Vault，并保留旧密码（不删除）。")
        return

    new_cred = graph_add_password(graph_token, object_id, display_name, _fmt_utc(end))
    new_key_id = str(new_cred.get("keyId", ""))
    secret_text = str(new_cred.get("secretText", ""))
    print(f"  新密码 keyId={new_key_id}")

    print(f"[步骤4] 换取 Key Vault token (scope={_config('KEYVAULT_SCOPE')}) ...")
    kv_token = get_token(_config("KEYVAULT_SCOPE"))

    print(f"[步骤5] 写入 Key Vault secret '{secret_name}' ...")
    try:
        kv_set_secret(kv_token, secret_name, secret_text, int(end.timestamp()))
    except SystemExit as exc:
        print(f"  !! 写入失败，回滚刚创建的新密码 {new_key_id} ...")
        try:
            graph_remove_password(graph_token, object_id, new_key_id)
            print("  已回滚新密码。")
        except SystemExit as rollback_exc:
            print(f"  回滚失败，请手动删除 keyId={new_key_id}: {rollback_exc}")
        raise exc
    print("  写入成功。")

    if old_key_ids and delete_old:
        print("[步骤6] 删除轮换前的旧密码 ...")
        for key_id in old_key_ids:
            if key_id == new_key_id:
                continue
            graph_remove_password(graph_token, object_id, key_id)
            print(f"  已删除 {key_id}")
    elif old_key_ids:
        print(f"[步骤6] 按配置保留旧密码（共 {len(old_key_ids)} 个，未删除）。")
    else:
        print("[步骤6] 没有旧密码需要处理。")

    if args.no_update:
        print("[步骤7] 跳过写入 credential.ini（--no-update）。")
        return
    print("[步骤7] 更新本地 credential.ini ...")
    old = read_credential()
    client_id = _config("TARGET_APP_CLIENT_ID") or old.get("client_id", "")
    save_credential(client_id, secret_text, end.strftime("%Y-%m-%d"))
    print(f"  已更新（client_id={client_id or '(空)'}, secret={_mask(secret_text)}）。")

    print("\n完成：新 secret 已写入 Key Vault，旧密码已清理。")
    print(f"  Key Vault secret : {secret_name}")
    print(f"  新密码 keyId     : {new_key_id}")
    print(f"  到期时间         : {_fmt_utc(end)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="定期轮换 Entra 应用 client secret 并写入 Key Vault")
    parser.add_argument("--debug-token", action="store_true",
                        help="解码 Graph token，检查配的是 Application 还是 Delegated 权限")
    parser.add_argument("--check-owner", action="store_true",
                        help="检查目标应用的所有者，确认服务主体满足 OwnedBy 权限前提")
    parser.add_argument("--check", action="store_true", help="只检查现有密码到期情况，不做修改")
    parser.add_argument("--dry-run", action="store_true", help="显示将要做的事，不实际调用 API")
    parser.add_argument("--days", type=int, help="新密码有效期天数（默认 ROTATE_DAYS）")
    parser.add_argument("--display-name", help="新密码显示名称（默认 rotated-YYYYMMDD）")
    parser.add_argument("--delete-old", dest="delete_old", action="store_true", default=None,
                        help="轮换后删除旧密码（默认，受 DELETE_OLD_SECRETS 配置影响）")
    parser.add_argument("--no-delete-old", dest="delete_old", action="store_false",
                        help="保留旧密码，不删除")
    parser.add_argument("--no-update", action="store_true", help="不写回 credential.ini")
    args = parser.parse_args()

    missing = [k for k in ("TENANT_ID", "API_CLIENT_ID", "API_CLIENT_SECRET", "KEYVAULT_NAME", "SECRET_NAME")
               if not _config(k)]
    if missing:
        raise SystemExit("以下配置为空，请先在 CONFIG 或环境变量中填写: " + ", ".join(missing))

    run(args)


if __name__ == "__main__":
    main()
