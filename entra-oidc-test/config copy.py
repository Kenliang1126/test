# 在 Entra 管理中心 → 应用注册 里复制以下值填进来

# 目录(租户) ID, 例如 "72f988bf-86f1-41af-91ab-2d7cd011db47"
# 建议填 GUID; 也可以填租户域名, 多租户测试可填 "organizations" / "common"
TENANT_ID = "XXX"

# 应用程序(客户端) ID
CLIENT_ID = "XXX"

# 客户端密码的 "值"(不是 "密码 ID")。留空则使用 PKCE —
# 此时必须在 应用注册 → 身份验证 → 高级设置 中把 "允许公共客户端流" 设为 "是",
# 否则 /token 会报 AADSTS7000218。
CLIENT_SECRET = "XXX"

# 必须与应用注册里配置的重定向 URI 完全一致
REDIRECT_URI = "XXX"
PORT = 5000

# Flask session 密钥(保存 state/nonce/PKCE verifier)。
# 留空则使用内置的本地测试用固定值; 仅本地使用无需修改。
SECRET_KEY = ""
