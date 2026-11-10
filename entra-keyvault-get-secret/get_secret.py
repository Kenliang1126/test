# -*- coding: utf-8 -*-
"""Blue Prism process "SUB - Azure Secret ID Update" 的 Python 复刻。

用纯 REST API（无 SDK，只依赖 requests）实现，对应 BP 流程的每一步:
  Scheduler(per UID) 定时触发本脚本，脚本读 4 个 session 变量作为输入:
    1) API Client ID      -> 服务主体的 client_id（用于认证）
    2) API Client Secret  -> 服务主体的 client_secret
    3) KeyVault Name      -> Key Vault 名称
    4) Secret Name        -> 要读取的 secret 名称
    外加 1 个 static: KeyVault Scope -> https://vault.azure.net/.default

流程步骤:
  步骤1 从本地 Credential Manager(credential.ini) 读取旧值:
        Client ID / Current Client Secret / Expiry Date
  步骤2 请求 token:
        POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
        body: grant_type=client_credentials&client_id=<API Client ID>
              &client_secret=<API Client Secret>&scope=<KeyVault Scope>
        header: Content-Type: application/x-www-form-urlencoded
  步骤3 调用 GetSecret():
        GET https://<KeyVault Name>.vault.azure.net/secrets/<Secret Name>?api-version=7.1
        header: Authorization: Bearer <token>
        不指定版本即返回最新版本，响应 JSON 的 value 字段就是最新 client secret
  步骤4 把最新值更新回本地 Credential Manager（Secret ID Update）

用法:
  python get_secret.py                 # 走完整 update 流程（读旧值 -> 取新值 -> 更新）
  python get_secret.py --no-update     # 只取最新值，不写回本地
  python get_secret.py --versions      # 列出所有版本及时间
  python get_secret.py --version <id>  # 读取指定版本（只读）
  python get_secret.py -q              # 只输出明文 value，方便被别的脚本接住
  python get_secret.py --output .secret

注意:
  - 服务主体的 client_secret(API Client Secret) 本身也是机密，请用环境变量，勿提交 git。
  - 用于认证的服务主体需有该 Key Vault 的 "Key Vault Secrets User" 权限（或访问策略 Get）。
"""

from __future__ import annotations

import argparse
import os
from configparser import ConfigParser
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

import requests

# =====================================================================
# 1) 需要你修改的配置（对应 BP 的 4 个 session 变量 + 2 个 static；可用同名环境变量覆盖）
# =====================================================================
CONFIG = {
    # 租户(目录) ID，token URI 用；填完整 GUID 或租户域名
    "TENANT_ID": "280bf41d-bf29-4912-9f4a-42def550b467",
    # session var 1: 用于认证的服务主体 client_id（不是业务应用的 client_id）
    "API_CLIENT_ID": "fdcdc6b6-f65c-44c3-a584-1891b0d8920f",
    # session var 2: 服务主体的 client_secret
    "API_CLIENT_SECRET": "",
    # session var 3: Key Vault 名称（纯名字，不带 .vault.azure.net）
    "KEYVAULT_NAME": "keyvaultkenliang1126",
    # session var 4: 要读取的 secret 名称
    "SECRET_NAME": "entra-oidc-client-secret",
    # static: Key Vault 的 scope；中国区改成 "https://vault.azure.cn/.default"
    "KEYVAULT_SCOPE": "https://vault.azure.net/.default",
    # static: Key Vault REST API 版本；流程里用 7.1，也可改 7.4
    "API_VERSION": "7.4",
}

ENV_MAP = {
    "TENANT_ID": "TENANT_ID",
    "API_CLIENT_ID": "API_CLIENT_ID",
    "API_CLIENT_SECRET": "API_CLIENT_SECRET",
    "KEYVAULT_NAME": "KEYVAULT_NAME",
    "SECRET_NAME": "SECRET_NAME",
}

# 本地 Credential Manager 的模拟：一个 ini 文件，存业务应用当前的 Client ID / Secret / Expiry Date
CREDENTIAL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "credential.ini")

# AADSTS 常见错误提示
TOKEN_ERROR_HINTS = {
    700016: "client_id 在该租户中不存在（检查 API_CLIENT_ID 和 TENANT_ID）。",
    7000215: "client_secret 错误（检查 API_CLIENT_SECRET）。",
    70011: "scope 无效（默认应为 https://vault.azure.net/.default）。",
    90002: "租户不存在或不可达（检查 TENANT_ID）。",
    65001: "服务主体未被授权访问该资源/scope。",
    7000218: "请求缺少客户端凭据。",
}


def _config(key: str) -> str:
    """配置读取：环境变量优先，其次 CONFIG。"""
    env_name = ENV_MAP.get(key)
    if env_name:
        value = os.environ.get(env_name, "").strip()
        if value:
            return value
    return str(CONFIG.get(key, "")).strip()


# =====================================================================
# 步骤1: 读取/更新本地 Credential Manager（模拟 BP Credential Manager）
# =====================================================================
def read_credential() -> dict[str, str]:
    """从 credential.ini 读取旧的 Client ID / Current Client Secret / Expiry Date。"""
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
    """把最新的 client secret（及过期日期）写回 credential.ini。"""
    parser = ConfigParser()
    parser["credential"] = {
        "client_id": client_id,
        "client_secret": client_secret,
        "expiry_date": expiry_date,
    }
    with open(CREDENTIAL_FILE, "w", encoding="utf-8") as f:
        parser.write(f)


# =====================================================================
# 步骤2: 请求 token（client_credentials）
# =====================================================================
def get_token() -> str:
    """按 BP 流程请求 access token。"""
    url = f"https://login.microsoftonline.com/{_config('TENANT_ID')}/oauth2/v2.0/token"
    # 等价 body 字符串（注意：不能加单引号）:
    #   grant_type=client_credentials&client_id=<API Client ID>&client_secret=<API Client Secret>&scope=<KeyVault Scope>
    body = urlencode({
        "grant_type": "client_credentials",
        "client_id": _config("API_CLIENT_ID"),
        "client_secret": _config("API_CLIENT_SECRET"),
        "scope": _config("KEYVAULT_SCOPE"),
    })
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(url, data=body, headers=headers, timeout=30)

    try:
        data = resp.json()
    except ValueError:
        data = {}

    if resp.status_code != 200 or "access_token" not in data:
        hint = ""
        for code in data.get("error_codes") or []:
            try:
                hint = TOKEN_ERROR_HINTS.get(int(code), "")
            except (TypeError, ValueError):
                continue
            if hint:
                break
        err = data.get("error_description") or data.get("error") or resp.text
        raise SystemExit(
            f"换取 access token 失败 (HTTP {resp.status_code}): {err}\n"
            + (f"提示: {hint}\n" if hint else "")
        )
    return data["access_token"]


# =====================================================================
# 步骤3: GetSecret() —— 读取最新版本 secret
# =====================================================================
def _vault_base() -> str:
    return f"https://{_config('KEYVAULT_NAME')}.vault.azure.net"


def get_secret_response(token: str, secret_name: str, version: str | None = None) -> dict[str, Any]:
    """调用 GetSecret()，返回完整 JSON。version 为 None 时即最新版本。"""
    path = f"{_vault_base()}/secrets/{secret_name}"
    if version:
        path += f"/{version}"
    params = {"api-version": _config("API_VERSION")}
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(path, headers=headers, params=params, timeout=30)

    try:
        body = resp.json()
    except ValueError:
        body = {}

    if resp.status_code == 401:
        raise SystemExit("GetSecret 返回 401: token 无效/过期，或 scope 与云环境不匹配。")
    if resp.status_code == 403:
        raise SystemExit(
            "GetSecret 返回 403: 服务主体没有该 secret 的读取权限。\n"
            + "注意：RBAC 的 'Reader' / 'Key Vault Reader' 只能看元数据，读不到 secret 值，改脚本无法绕过。\n"
            + "需要数据面权限，二选一：\n"
            + "  1) RBAC：分配 'Key Vault Secrets User'，可把 scope 限定到单个 secret，权限最小；\n"
            + "  2) 访问策略：给该服务主体勾选 Secret 的 'Get'（只需 Get，不必 List）。"
        )
    if resp.status_code == 404:
        raise SystemExit(
            f"GetSecret 返回 404: 找不到 secret '{secret_name}'，"
            + "请检查 KEYVAULT_NAME 和 SECRET_NAME 是否正确。"
        )
    if resp.status_code != 200:
        raise SystemExit(f"GetSecret 失败 (HTTP {resp.status_code}): {resp.text}")
    return body


def list_versions(token: str, secret_name: str) -> None:
    """列出 secret 的所有版本及时间（只读）。"""
    path = f"{_vault_base()}/secrets/{secret_name}/versions"
    params = {"api-version": _config("API_VERSION")}
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(path, headers=headers, params=params, timeout=30)
    body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}

    if resp.status_code == 403:
        raise SystemExit("列出版本返回 403: 服务主体没有读取权限。")
    if resp.status_code == 404:
        raise SystemExit(f"找不到 secret '{secret_name}'。")
    if resp.status_code != 200:
        raise SystemExit(f"列出版本失败 (HTTP {resp.status_code}): {resp.text}")

    versions = body.get("value", [])
    if not versions:
        print("该 secret 没有任何版本记录。")
        return
    print(f"{secret_name} 的版本（新的在前）:")
    for v in versions:
        attrs = v.get("attributes", {})
        print(f"  {v.get('id')}")
        print(
            f"      created={_fmt_ts(attrs.get('created'))}  "
            + f"updated={_fmt_ts(attrs.get('updated'))}  enabled={attrs.get('enabled', True)}"
        )


def _fmt_ts(seconds) -> str:
    if not seconds:
        return "-"
    try:
        return datetime.fromtimestamp(int(seconds), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OSError):
        return str(seconds)


def _expiry_date(seconds) -> str:
    """把 Key Vault 返回的 exp(unix 秒) 转成 YYYY-MM-DD，未设置返回空串。"""
    if not seconds:
        return ""
    try:
        return datetime.fromtimestamp(int(seconds), tz=timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError):
        return ""


def _mask(s: str) -> str:
    if not s:
        return "(空)"
    return s[:6] + "..." if len(s) > 9 else s


# =====================================================================
# 主流程
# =====================================================================
def run(args) -> None:
    secret_name = args.secret_name or _config("SECRET_NAME")

    print("[步骤2] 请求 access token ...")
    token = get_token()

    if args.versions:
        list_versions(token, secret_name)
        return

    if args.version:
        # 指定版本：只读展示，不参与 update
        body = get_secret_response(token, secret_name, args.version)
        value = body.get("value", "")
        print(f"[步骤3] 指定版本 {args.version} 的 secret value: {value}")
        return

    print("[步骤3] GetSecret() 读取最新版本 ...")
    body = get_secret_response(token, secret_name)
    value = body.get("value", "")
    attrs = body.get("attributes", {})
    expiry = _expiry_date(attrs.get("exp"))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(value)
        print(f"已写入 {args.output}")

    if args.quiet:
        print(value)
        return

    print("[步骤1] 读取本地 Credential Manager（credential.ini）的旧值 ...")
    old = read_credential()
    print(f"  Client ID        : {old.get('client_id') or '(未记录)'}")
    print(f"  Current Secret   : {_mask(old.get('client_secret', ''))}")
    print(f"  Expiry Date      : {old.get('expiry_date') or '(未记录)'}")
    print()
    print("  Key Vault 最新 secret :", value)
    print("  过期时间(attributes.exp):", expiry or "未设置")

    if args.no_update:
        print()
        print("（--no-update：只获取，不写回本地 Credential Manager）")
        return

    print("[步骤4] 更新本地 Credential Manager ...")
    if old.get("client_secret") == value:
        print("  结果：最新 secret 与本地一致，无需更新。")
    else:
        save_credential(
            client_id=old.get("client_id", ""),
            client_secret=value,
            expiry_date=expiry or old.get("expiry_date", ""),
        )
        print("  结果：检测到新 secret，已更新 credential.ini。")


def main():
    parser = argparse.ArgumentParser(description="Blue Prism 'Azure Secret ID Update' 流程的 Python 复刻")
    parser.add_argument("secret_name", nargs="?", help="secret 名称（缺省用配置里的 SECRET_NAME）")
    parser.add_argument("--versions", action="store_true", help="列出所有版本（只读）")
    parser.add_argument("--version", help="读取指定版本 ID（只读）")
    parser.add_argument("--no-update", action="store_true", help="只获取最新值，不写回本地")
    parser.add_argument("-q", "--quiet", action="store_true", help="只输出明文 value")
    parser.add_argument("--output", help="把 value 写入指定文件")
    args = parser.parse_args()

    missing = [k for k in ("TENANT_ID", "API_CLIENT_ID", "API_CLIENT_SECRET", "KEYVAULT_NAME", "SECRET_NAME")
               if not _config(k)]
    if missing:
        raise SystemExit(
            "以下配置为空，请先在脚本顶部 CONFIG 或环境变量中填写: " + ", ".join(missing)
        )

    run(args)


if __name__ == "__main__":
    main()
