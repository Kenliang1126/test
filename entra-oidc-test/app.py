"""Entra ID (Azure AD) OIDC SSO 最小验证工具

准备(二选一):
  A. 客户端密码模式(最直观)
     1. Entra 管理中心 → 应用注册 → 新注册
        账户类型: "仅此组织目录中的账户" 或 "任何组织目录中的账户"
        重定向 URI: 平台选 "Web", 填 http://localhost:5000/callback
     2. "证书和密码" → 新建客户端密码 → 复制 "值" 到 config.py 的 CLIENT_SECRET
     3. 复制 "应用程序(客户端) ID" → CLIENT_ID, "目录(租户) ID" → TENANT_ID
  B. PKCE 模式(不需要密码)
     同上但跳过第 2 步, 并在 "身份验证" 中把 "允许公共客户端流" 设为 "是",
     CLIENT_SECRET 留空即可。

运行:
  pip install -r requirements.txt
  python app.py
  浏览器打开 http://localhost:5000

流程: /login → 微软授权页 → /callback(code) → /token → 校验 id_token → 展示结果
"""

import base64
import hashlib
import html
import json
import os
import secrets

import jwt
import requests
from flask import Flask, redirect, request, session
from urllib.parse import urlencode

import config

SCOPE = "openid profile email"
TENANT = config.TENANT_ID.strip() or "common"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT}"
AUTHORIZE_URL = f"{AUTHORITY}/oauth2/v2.0/authorize"
TOKEN_URL = f"{AUTHORITY}/oauth2/v2.0/token"
JWKS_URL = f"{AUTHORITY}/discovery/v2.0/keys"

app = Flask(__name__)
# 固定密钥, 这样重启服务后未过期的 session(含 state/nonce/verifier)仍然有效。
# 仅用于本地测试; 若要暴露到公网, 请在 config.py 设置随机 SECRET_KEY。
app.secret_key = config.SECRET_KEY.strip() or "entra-oidc-test-local-only-do-not-expose"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",  # 微软经顶层 GET 跳回时需要携带 cookie
    SESSION_COOKIE_SECURE=False,  # 本地是 http, 不能设为 True
)

BASE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Entra ID OIDC SSO 测试</title>
<style>
:root{--ok:#0f7b3f;--bad:#b42318;--line:#e4e7ec;--fg:#101828;--muted:#667085}
*{box-sizing:border-box}
body{margin:0;padding:32px 16px;background:#f7f8fa;color:var(--fg);
     font:15px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
.wrap{max-width:880px;margin:0 auto}
h1{font-size:21px;margin:0 0 4px}
h2{font-size:15px;margin:0 0 10px}
.sub{color:var(--muted);font-size:13px;margin:0 0 20px}
.card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin-bottom:14px}
.step{display:flex;gap:12px;padding:10px 0;border-bottom:1px dashed var(--line)}
.step:last-child{border-bottom:0}
.mark{flex:0 0 22px;width:22px;height:22px;border-radius:50%;color:#fff;font-size:13px;
      display:flex;align-items:center;justify-content:center;margin-top:2px}
.ok .mark{background:var(--ok)} .bad .mark{background:var(--bad)}
.step b{display:block;font-weight:600}
pre{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;overflow:auto;
    font-size:12.5px;margin:8px 0 0;white-space:pre-wrap;word-break:break-all}
code{font-size:12.5px;word-break:break-all}
.btn{display:inline-block;background:#0b5fff;color:#fff;text-decoration:none;
     padding:10px 18px;border-radius:8px;font-weight:600}
.btn:hover{background:#0847cc}
table{width:100%;border-collapse:collapse;font-size:13.5px}
td{border-bottom:1px solid var(--line);padding:7px 8px;vertical-align:top}
td:first-child{width:190px;color:var(--muted)}
.muted{color:var(--muted);font-size:13px}
.bad-text{color:var(--bad);font-weight:600}
details{margin-top:10px}
summary{cursor:pointer;color:#0b5fff;font-size:13.5px}
</style>
</head>
<body><div class="wrap">
<h1>Entra ID OIDC SSO 测试</h1>
<p class="sub">Authorization Code Flow · __MODE__ · __ISSUER__</p>
__BODY__
</div></body></html>"""


def page(body: str) -> str:
    mode = "Client Secret" if config.CLIENT_SECRET else "PKCE"
    return (
        BASE.replace("__MODE__", mode)
        .replace("__ISSUER__", html.escape(AUTHORITY))
        .replace("__BODY__", body)
    )


def steps_html(steps) -> str:
    out = []
    for title, ok, detail in steps:
        detail_html = f"<pre>{html.escape(detail)}</pre>" if detail else ""
        out.append(
            f'<div class="step {"ok" if ok else "bad"}">'
            f'<span class="mark">{"✓" if ok else "✗"}</span>'
            f"<div><b>{html.escape(title)}</b>{detail_html}</div></div>"
        )
    return "".join(out)


def mask_tokens(tokens: dict) -> str:
    shown = dict(tokens)
    for key in ("access_token", "refresh_token", "id_token"):
        value = shown.get(key)
        if isinstance(value, str) and len(value) > 80:
            shown[key] = value[:48] + f"... (共 {len(value)} 字符)"
    return json.dumps(shown, indent=2, ensure_ascii=False)


TOKEN_ERROR_HINTS = {
    7000218: (
        "请求缺少客户端凭据。二选一: 在 config.py 填 CLIENT_SECRET"
        "(应用注册 → 证书和密码 → 新建客户端密码, 复制“值”);"
        "或到 应用注册 → 身份验证 → 高级设置 → 把“允许公共客户端流”设为“是”, "
        "然后重启本工具走 PKCE。"
    ),
    7000215: "CLIENT_SECRET 不正确: 要填“证书和密码”里的“值”(不是“密码 ID”), 且不要带空格或换行。",
    7000222: "客户端密码已过期, 请重新创建并更新 config.py。",
    50011: "重定向 URI 不匹配: 必须与 Entra 中注册的完全一致, 且平台选 Web。",
    65001: "用户或租户尚未同意该应用的权限, 请用管理员账号登录并授予同意。",
    700054: "该账户类型不受支持, 检查应用注册的“支持的账户类型”与 TENANT_ID 是否匹配。",
    9002326: "该重定向 URI 注册在 Web 平台却被当作公共客户端换取令牌: "
    "把 URI 改注册到“单页应用程序”平台, 或改用 CLIENT_SECRET。",
}


def explain_token_error(tokens: dict) -> str:
    for code in tokens.get("error_codes") or []:
        try:
            hint = TOKEN_ERROR_HINTS.get(int(code))
        except (TypeError, ValueError):
            continue
        if hint:
            return hint
    return ""


def new_pkce_pair():
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    return verifier, challenge


def verify_id_token(id_token: str):
    """用微软 JWKS 验签, 并校验 issuer / audience / 有效期 / nonce。"""
    unverified = jwt.decode(id_token, options={"verify_signature": False})
    issuer = unverified.get("iss", "")
    if not issuer.startswith(("https://login.microsoftonline.com/", "https://sts.windows.net/")):
        raise ValueError(f"id_token 的 issuer 不是 Microsoft: {issuer}")

    jwks = requests.get(JWKS_URL, timeout=30).json()
    header = jwt.get_unverified_header(id_token)
    key_data = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
    if key_data is None:
        raise ValueError(f"JWKS 中找不到 kid={header.get('kid')}")

    algorithm = header.get("alg", "RS256")
    signing_key = jwt.PyJWK(key_data, algorithm=algorithm).key
    claims = jwt.decode(
        id_token,
        signing_key,
        algorithms=[algorithm],
        audience=config.CLIENT_ID,
        issuer=issuer,
        options={"require": ["exp", "iat", "aud", "iss"]},
    )

    tenant_hint = config.TENANT_ID.strip()
    if tenant_hint.count("-") == 4 and claims.get("tid") != tenant_hint:
        raise ValueError(f"tid ({claims.get('tid')}) 与配置的 TENANT_ID 不一致")

    if session.get("nonce") and claims.get("nonce") != session.get("nonce"):
        raise ValueError("id_token 中的 nonce 与发起登录时不一致(可能被重放)")

    return claims, algorithm


@app.after_request
def no_store(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def index():
    configured = bool(config.CLIENT_ID.strip() and config.TENANT_ID.strip())
    warning = (
        ""
        if configured
        else '<p class="bad-text">请先在 config.py 中填写 TENANT_ID 和 CLIENT_ID。</p>'
    )
    if not config.CLIENT_SECRET:
        warning += (
            '<p class="muted">当前为 PKCE 模式: 应用注册里必须把“允许公共客户端流”设为“是”, '
            "否则 /token 会报 AADSTS7000218。</p>"
        )
    body = f"""
<div class="card">
  <table>
    <tr><td>授权端点</td><td><code>{html.escape(AUTHORIZE_URL)}</code></td></tr>
    <tr><td>租户 TENANT_ID</td><td><code>{html.escape(config.TENANT_ID or "(未配置)")}</code></td></tr>
    <tr><td>客户端 ID</td><td><code>{html.escape(config.CLIENT_ID or "(未配置)")}</code></td></tr>
    <tr><td>回调地址</td><td><code>{html.escape(config.REDIRECT_URI)}</code></td></tr>
    <tr><td>认证方式</td><td>{"客户端密码" if config.CLIENT_SECRET else "PKCE(无客户端密码)"}</td></tr>
    <tr><td>Scope</td><td><code>{SCOPE}</code></td></tr>
  </table>
  {warning}
</div>
<div class="card">
  <a class="btn" href="/login">使用 Microsoft 帐户登录</a>
  <p class="muted">点击后跳转到微软登录页;认证成功后自动回到本工具, 并逐步显示验证结果。</p>
</div>
"""
    return page(body)


@app.get("/login")
def login():
    verifier, challenge = new_pkce_pair()
    session["state"] = secrets.token_urlsafe(24)
    session["nonce"] = secrets.token_urlsafe(24)
    session["verifier"] = verifier

    params = {
        "client_id": config.CLIENT_ID,
        "response_type": "code",
        "redirect_uri": config.REDIRECT_URI,
        "response_mode": "query",
        "scope": SCOPE,
        "state": session["state"],
        "nonce": session["nonce"],
        "prompt": "select_account",
    }
    if not config.CLIENT_SECRET:
        params["code_challenge"] = challenge
        params["code_challenge_method"] = "S256"

    return redirect(f"{AUTHORIZE_URL}?{urlencode(params)}")


@app.get("/callback")
def callback():
    steps = []

    error = request.args.get("error")
    if error:
        steps.append(
            (
                "微软返回错误",
                False,
                f"{error}: {request.args.get('error_description', '')}",
            )
        )
        return page(f'<div class="card">{steps_html(steps)}</div>')

    state = request.args.get("state")
    expected = session.get("state")
    if not state or state != expected:
        if not expected:
            reason = (
                "服务端会话为空 —— 浏览器没有把 session cookie 带回来。"
                "常见原因: 访问首页用的主机名与回调地址不同(如 127.0.0.1 与 localhost 混用, cookie 不共享)、"
                "cookie 被浏览器拦截或刚被清除、或回调链接来自历史记录。"
            )
        else:
            reason = (
                "会话里有 state 但与回传值不同 —— 常见原因: 期间又在别的标签页发起了一次登录, "
                "后一次覆盖了前一次; 或回调链接是旧的历史记录。"
            )
        body = f"""
<div class="card">
  <p class="bad-text">state 校验失败, 无法确认该回调来自本次登录。</p>
  <table>
    <tr><td>回调中的 state</td><td><code>{html.escape(state or "(缺失)")}</code></td></tr>
    <tr><td>会话中的 state</td><td><code>{html.escape(expected or "(会话为空)")}</code></td></tr>
    <tr><td>请求 Host</td><td><code>{html.escape(request.host)}</code></td></tr>
    <tr><td>REDIRECT_URI</td><td><code>{html.escape(config.REDIRECT_URI)}</code></td></tr>
  </table>
  <p class="muted">{html.escape(reason)}</p>
  <p class="muted">排查顺序: 1) 只用 <code>{html.escape(config.REDIRECT_URI)}</code> 这个主机名打开首页, 不要混用
  127.0.0.1; 2) 清除本站 cookie 后重试; 3) 只保留一个登录标签页; 4) 确认浏览器允许 cookie。</p>
  <a class="btn" href="/login">重新发起登录</a>
</div>
"""
        return page(body)
    steps.append(("校验 state", True, "回调 state 与本地会话一致, 排除 CSRF"))

    code = request.args.get("code")
    if not code:
        steps.append(("获取授权码", False, "回调里没有 code 参数"))
        return page(f'<div class="card">{steps_html(steps)}</div>')
    steps.append(("获取授权码", True, f"code={code[:24]}..."))

    payload = {
        "client_id": config.CLIENT_ID,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config.REDIRECT_URI,
        "scope": SCOPE,
    }
    if config.CLIENT_SECRET:
        payload["client_secret"] = config.CLIENT_SECRET
    else:
        payload["code_verifier"] = session.get("verifier", "")

    try:
        resp = requests.post(TOKEN_URL, data=payload, timeout=30)
    except requests.RequestException as exc:
        steps.append(("调用 /token 换取令牌", False, f"网络错误: {exc}"))
        return page(f'<div class="card">{steps_html(steps)}</div>')

    try:
        tokens = resp.json()
    except ValueError:
        tokens = {"raw": resp.text}

    if resp.status_code != 200 or "id_token" not in tokens:
        steps.append(
            (
                "调用 /token 换取令牌",
                False,
                f"HTTP {resp.status_code}\n{json.dumps(tokens, indent=2, ensure_ascii=False)}",
            )
        )
        hint = explain_token_error(tokens)
        banner = f'<div class="card"><p class="bad-text">{html.escape(hint)}</p></div>' if hint else ""
        return page(banner + f'<div class="card">{steps_html(steps)}</div>')
    steps.append(
        (
            "调用 /token 换取令牌",
            True,
            f"HTTP 200, 返回 access_token / id_token, scope={tokens.get('scope', '-')}",
        )
    )

    try:
        claims, algorithm = verify_id_token(tokens["id_token"])
    except Exception as exc:  # noqa: BLE001 - 需要把任何校验失败展示给用户
        steps.append(("验证 id_token", False, f"{type(exc).__name__}: {exc}"))
        return page(f'<div class="card">{steps_html(steps)}</div>')

    steps.append(
        (
            "验证 id_token 签名与声明",
            True,
            f"JWKS 验签通过 (alg={algorithm}), aud/client_id、iss、exp、tid、nonce 均校验通过",
        )
    )
    steps.append(
        (
            "SSO 登录成功",
            True,
            f"用户: {claims.get('name') or claims.get('preferred_username') or claims.get('oid')}",
        )
    )

    user_rows = "".join(
        f"<tr><td>{html.escape(label)}</td><td><code>{html.escape(str(claims.get(claim, '-')))}</code></td></tr>"
        for label, claim in [
            ("显示名称 name", "name"),
            ("登录名 preferred_username", "preferred_username"),
            ("邮箱 email", "email"),
            ("对象 ID oid", "oid"),
            ("租户 ID tid", "tid"),
            ("会话 ID sid", "sid"),
            ("颁发时间 iat", "iat"),
            ("过期时间 exp", "exp"),
        ]
    )

    body = f"""
<div class="card">{steps_html(steps)}</div>
<div class="card">
  <h2>用户信息(来自 id_token)</h2>
  <table>{user_rows}</table>
</div>
<div class="card">
  <details><summary>完整 id_token claims</summary><pre>{html.escape(json.dumps(claims, indent=2, ensure_ascii=False))}</pre></details>
  <details><summary>/token 响应(令牌已截断)</summary><pre>{html.escape(mask_tokens(tokens))}</pre></details>
  <details><summary>原始 id_token(已截断)</summary><pre>{html.escape(mask_tokens({"id_token": tokens["id_token"]}))}</pre></details>
</div>
<div class="card"><a class="btn" href="/login">再登录一次(验证免密 SSO)</a></div>
"""
    return page(body)


if __name__ == "__main__":
    if not config.CLIENT_ID.strip() or not config.TENANT_ID.strip():
        print("[!] 请先在 config.py 中填写 TENANT_ID 和 CLIENT_ID")
    print(f"[*] 打开 http://localhost:{config.PORT} 开始测试")
    app.run(host="127.0.0.1", port=config.PORT, debug=False)
