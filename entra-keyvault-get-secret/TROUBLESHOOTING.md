# Entra 应用 Secret 轮换排障记录

> 记录时间：2026-10-30
> 涉及脚本：`rotate_secret.py`（写入端）、`get_secret.py`（读取端，未改动）

## 一、目标

定期为 Entra 应用生成新的 client secret，写入 Key Vault，并清理旧密码，供 OIDC 应用运行时读取。

```
rotate_secret.py（定时）  →  Entra addPassword  →  Key Vault PUT  →  删除旧密码
get_secret.py（运行时）   →  Key Vault GET      →  拿到当前 secret
```

## 二、环境信息

| 项 | 值 |
|---|---|
| 租户 ID | `280bf41d-bf29-4912-9f4a-42def550b467` |
| 执行方（服务主体）appId | `fdcdc6b6-f65c-44c3-a584-1891b0d8920f` |
| 目标应用 objectId | `cec141da-2115-46b3-925d-31c4f7f66576` |
| 认证方式 | `client_credentials`（无用户，纯应用身份） |
| Graph scope | `https://graph.microsoft.com/.default` |

> 密钥不落文档，统一用环境变量 `API_CLIENT_SECRET` 注入。

## 三、问题现象

```
[步骤1] 换取 Microsoft Graph token ...          ✅
[步骤2] 列出现有 client secret ...               ✅
[步骤3] 生成新 client secret ...                 ❌ 403
```

错误体：

```json
{"error":{"code":"Authorization_RequestDenied",
          "message":"Insufficient privileges to complete the operation."}}
```

同时发现列表里 `剩余=未知`。

## 四、根因分析

### 1. 能读不能写 → 权限缺失

`GET /applications/{id}/passwordCredentials` 成功，`POST /applications/{id}/addPassword` 403。
说明调用方只有读权限，没有写权限。

### 2. 加了权限仍 403 → 权限类型选错（Delegated vs Application）

| 对比项 | Delegated（委托） | Application（应用程序） |
|---|---|---|
| 授权方式 | 用户登录后代为操作 | 应用自己（client_credentials） |
| token 中的声明 | `scp` | `roles` |
| 对本脚本是否有效 | ❌ 无效 | ✅ 必须 |

最初在门户添加的是 **Delegated** 的 `Application.ReadWrite.All`，状态显示"已授予"，
但 `client_credentials` 拿到的 token 只有 Application 权限，Delegated 对它**完全不生效**。

**判据**：解码 token，看 `roles` 是否为空。

### 3. 改成 `Application.ReadWrite.OwnedBy` 后仍 403 → 缺 owner 关系

`OwnedBy` 的语义是"只能管理**自己拥有**的应用"。服务主体虽已拿到该角色，
但不是目标应用的 owner，因此写操作依然 `Authorization_RequestDenied`。

### 4. PowerShell 侧的两个额外坑

| 报错 | 原因 | 处理 |
|---|---|---|
| `400 Request_UnsupportedQuery` | `applications` 上按 `appId` 过滤属 advanced query，需 `ConsistencyLevel: eventual` | 改用 `Get-MgApplication -ApplicationId <guid>`，该接口同时接受 objectId 和 appId |
| `403 Authorization_RequestDenied` | `Connect-MgGraph` 登录的账号本身没有 `Application.ReadWrite.All`（scope 被静默丢弃），或连错租户 | 用 `-TenantId` 显式指定，并用 `Get-MgContext` 检查 `Scopes` |

> 关键认知：`Connect-MgGraph -Scopes "Application.ReadWrite.All"` 只是**请求**权限；
> 账号非管理员或租户禁用用户同意时，scope 不会出现在 token 里，连接却仍然成功。

### 5. `剩余=未知` → 日期解析 bug

`_parse_iso` 只匹配 `%Y-%m-%dT%H:%M:%SZ`，而 Graph 返回带毫秒的
`2027-04-28T09:23:17.783Z`，解析失败返回 `None`，导致显示"未知"。

已改为 `datetime.fromisoformat(value.replace("Z", "+00:00"))` 并保留 `%f` 兜底。

## 五、最终可用配置

两种方案二选一：

### 方案 A：最小权限（推荐长期使用）

1. 服务主体 `fdcdc6b6-...` 添加 **应用程序权限** `Application.ReadWrite.OwnedBy`
2. **授予管理员同意**，状态须为"已授予"
3. 把服务主体设为目标应用 `cec141da-...` 的 **所有者**

```powershell
Connect-MgGraph -TenantId "280bf41d-bf29-4912-9f4a-42def550b467" -Scopes "Application.ReadWrite.All"

$app = Get-MgApplication -ApplicationId "cec141da-2115-46b3-925d-31c4f7f66576"
$sp  = Get-MgServicePrincipal -Filter "appId eq 'fdcdc6b6-f65c-44c3-a584-1891b0d8920f'"

New-MgApplicationOwnerByRef -ApplicationId $app.Id `
  -BodyParameter @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($sp.Id)" }

Get-MgApplicationOwner -ApplicationId $app.Id | Select-Object Id, DisplayName
```

撤销 owner 关系：

```powershell
$uri = 'https://graph.microsoft.com/v1.0/applications/' + $app.Id + '/owners/' + $sp.Id + '/$ref'
Invoke-MgGraphRequest -Method DELETE -Uri $uri
```

### 方案 B：`Application.ReadWrite.All`（最快，免设 owner）

1. 服务主体添加 **应用程序权限** `Application.ReadWrite.All`
2. 授予管理员同意
3. 无需 owner 关系

> 方案 B 不依赖 owner，删掉 owner 也不影响；方案 A 删掉 owner 会立即恢复 403。

### 另需 Key Vault 写权限

| 授权方式 | 所需 |
|---|---|
| RBAC | 角色 `Key Vault Secrets Officer` |
| 访问策略 | Secret 权限勾选 `Set` |

（`Secrets User` 只有读，不够。）

## 六、脚本新增能力

| 参数 / 配置 | 作用 |
|---|---|
| `--debug-token` | 解码 Graph access token，打印 `aud` / `appid` / `roles` / `scp`，判断是 Application 还是 Delegated |
| `--check-owner` | 列出目标应用 owner，判断服务主体是否满足 `OwnedBy` 前提 |
| `--check` | 只看到期情况，不做修改 |
| `--dry-run` | 只打印将要执行的动作 |
| `--delete-old` / `--no-delete-old` | 显式控制是否删除旧密码 |
| `DELETE_OLD_SECRETS`（配置 / 环境变量） | 长期默认值，命令行优先 |
| `--days N` | 新密码有效期 |
| `--no-update` | 不写回 `credential.ini` |

`--debug-token` 正常输出示例：

```
roles : ['Application.ReadWrite.OwnedBy']
scp   : None
=> app-only token，已带 application 权限(roles)，权限配置正确。
```

`roles` 为空即说明只配了 Delegated 权限。

## 七、常用命令

```powershell
# 权限自检
python d:\Code\entra-keyvault-get-secret\rotate_secret.py --debug-token
python d:\Code\entra-keyvault-get-secret\rotate_secret.py --check-owner

# 预演
python d:\Code\entra-keyvault-get-secret\rotate_secret.py --check
python d:\Code\entra-keyvault-get-secret\rotate_secret.py --dry-run

# 正式轮换（默认删旧密码）
python d:\Code\entra-keyvault-get-secret\rotate_secret.py

# 首次验证建议保留旧密码
python d:\Code\entra-keyvault-get-secret\rotate_secret.py --no-delete-old
```

## 八、踩坑清单

1. **权限类型**：必须选"应用程序权限"，不是"委托的权限"。`client_credentials` 只认前者。
2. **必须授予管理员同意**：状态列要显示"已授予"。
3. **`OwnedBy` 必须配 owner**：否则读写都不稳，写必 403。
4. **权限生效有延迟**：同意后等 1~2 分钟。脚本每次都会重新取 token，无需清缓存。
5. **加权限的对象别搞错**：加在服务主体 `fdcdc6b6-...` 上，不是目标应用 `cec141da-...`。
6. **`Get-MgApplication` 别用 `appId` 过滤**：直接用 `-ApplicationId`。
7. **`Connect-MgGraph` 要用 `-TenantId`**：多租户账号容易连错。
8. **Key Vault 写权限**：`Secrets User` 不够，需要 `Secrets Officer` 或 `Set`。
9. **不要反复盲跑**：`addPassword` 成功会真的生成密码；失败回滚的保护仅覆盖"写 Key Vault 失败"场景。

## 九、安全建议

- `API_CLIENT_SECRET` 优先用环境变量，不要硬编码在脚本里，更不要提交 git。
- 测试用 `Application.ReadWrite.All` 跑通后，建议换回 `OwnedBy` + owner 收敛权限。
- 定期用 `--check` 做到期预警，到期前 30 天内执行正式轮换。
