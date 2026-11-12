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

# 公司出站代理。访问 login.microsoftonline.com 必须经过代理时填写。
# 形如 "http://proxy.corp.example.com:8080"
# 需要认证时 "http://user:password@proxy.corp.example.com:8080"
# (密码里的 @ : / 等字符要做 URL 编码, 例如 @ -> %40)
# 留空则沿用环境变量 HTTPS_PROXY / HTTP_PROXY; 都没有就直连。
PROXY = ""

# 公司网络的 HTTPS 检查(中间人代理)会让 Python 报
#   SSLCertVerificationError: unable to get local issuer certificate
# 把公司根证书的 PEM 文件路径填在这里(绝对路径); 留空则只用默认证书库。
# 有多个根证书时, 用 cat 合并成一个 .pem 再填该文件路径。
# 示例: CA_BUNDLE = "/etc/ssl/certs/company-root.pem"
CA_BUNDLE = ""