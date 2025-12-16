# Cloudflare R2 WebDAV Server

[English](README_EN.md) | 简体中文

基于 Cloudflare Workers 和 R2 存储的企业级 WebDAV 服务器，支持完整的文件管理功能和多层安全认证。

## 目录

- [核心特性](#核心特性)
- [安全功能](#安全功能)
- [快速部署](#快速部署)
- [使用指南](#使用指南)
- [常见问题](#常见问题)
- [本地开发](#本地开发)
- [文档索引](#文档索引)

## 核心特性

### 文件管理

- 完全兼容 WebDAV 协议，支持所有标准客户端
- 支持文件上传、下载、删除、移动、复制操作
- 支持目录创建和浏览
- 内置现代化 Web 文件管理界面

### 技术架构

- 基于 Cloudflare Workers 边缘计算，全球加速访问
- 使用 Cloudflare R2 作为存储后端（慷慨的免费额度）
- 无需管理服务器，自动扩展
- 支持自定义存储配额和文件大小限制

## 安全功能

本项目实现了企业级三层安全防护体系，您可以根据需要选择启用。

### 基础安全（必需）

- **密码加密存储** - PBKDF2 哈希算法，100,000 次迭代
- **JWT 令牌认证** - 访问令牌（15分钟）+ 刷新令牌（7天）
- **暴力破解防护** - 三维限流（IP/用户/组合），5次失败后封禁
- **文件安全验证** - 扩展名白名单 + MIME 类型检查
- **存储配额管理** - 默认 10GB 总容量，单文件 100MB

### 双因素认证（可选）

- **TOTP 动态验证码** - 兼容 Google Authenticator 等标准应用
- **恢复码备份** - 10 个一次性使用的恢复密钥
- **WebDAV 集成** - 桌面客户端支持通过自定义头部传递验证码
- **强制执行** - 启用后所有登录方式都需要 2FA 验证

### Passkey 无密码登录（可选）

- **生物识别** - Touch ID、Face ID、Windows Hello
- **硬件密钥** - YubiKey、Titan Key 等 FIDO2 安全密钥
- **抗钓鱼攻击** - 凭证与域名绑定，无法在假冒网站使用
- **多设备支持** - 可注册多个认证器
- **WebAuthn 标准** - 符合 W3C Web Authentication API

详细的安全功能配置请参考 [安全功能设置指南](docs/SECURITY_SETUP.md)。

## 快速部署

选择一种部署方式开始使用：

### 方式 1：一键部署（最简单）

适合快速体验和个人使用。

1. 点击下方按钮开始部署：

   [![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/amm10090/CFr2-webdav)

2. 按照页面提示完成部署
3. 查看 [安全功能设置指南](docs/SECURITY_SETUP.md) 配置密码和安全功能

**注意**：需要有 Cloudflare 账户。如果您还没有账户，可以在 [Cloudflare 官网](https://www.cloudflare.com) 免费注册。

### 方式 2：GitHub Actions 自动部署（推荐）

适合需要版本控制和团队协作的场景。

#### 准备工作

1. **Fork 本仓库** 到您的 GitHub 账户
2. **创建 Cloudflare 账户**（如果还没有）
3. **创建 R2 存储桶**：
   - 登录 Cloudflare Dashboard
   - 进入 R2 → Create bucket
   - 输入桶名称（如 `my-webdav-storage`）

4. **创建 KV 命名空间**（用于存储认证和限流数据）：

   使用 Wrangler CLI 或在 Cloudflare Dashboard 创建以下 3 个命名空间：

   ```bash
   # 使用 Wrangler CLI（推荐）
   npx wrangler kv:namespace create "RATE_LIMIT_KV"
   npx wrangler kv:namespace create "QUOTA_KV"
   npx wrangler kv:namespace create "TOTP_KV"
   ```

   记录每个命名空间的 ID，稍后需要配置到 GitHub Secrets。

5. **生成密码哈希和 JWT 密钥**：

   ```bash
   # 克隆仓库到本地
   git clone https://github.com/your-username/CFr2-webdav.git
   cd CFr2-webdav

   # 安装依赖
   npm install

   # 生成密码哈希（将 your-password 替换为您的密码）
   node -e "
   const crypto = require('crypto');
   const password = 'your-password';
   const salt = crypto.randomBytes(16);
   const iterations = 100000;
   crypto.pbkdf2(password, salt, iterations, 32, 'sha256', (err, derivedKey) => {
     if (err) throw err;
     console.log('PASSWORD_HASH=v1:' + iterations + ':' + salt.toString('base64') + ':' + derivedKey.toString('base64'));
   });
   "

   # 生成 JWT 密钥
   node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(32).toString('base64'));"
   ```

6. **获取 Cloudflare API Token**：
   - 访问 [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)
   - 点击 "Create Token"
   - 使用 "Edit Cloudflare Workers" 模板
   - 权限设置：
     - Account → Cloudflare Workers Scripts → Edit
     - Account → Account Settings → Read
   - 创建后复制 Token（仅显示一次）

7. **获取 Cloudflare 账户 ID**：
   - 登录 Cloudflare Dashboard
   - 在右侧栏可以看到 Account ID

#### 配置 GitHub Secrets

在您 Fork 的仓库中：**Settings → Secrets and variables → Actions → New repository secret**

添加以下 Secrets（全部必需）：

| Secret 名称             | 说明                   | 示例                         |
| ----------------------- | ---------------------- | ---------------------------- |
| `CLOUDFLARE_API_TOKEN`  | API Token              | `abc123...`                  |
| `CLOUDFLARE_ACCOUNT_ID` | 账户 ID                | `1234567890abcdef...`        |
| `BUCKET_NAME`           | R2 存储桶名称          | `my-webdav-storage`          |
| `USERNAME`              | 管理员用户名           | `admin`                      |
| `PASSWORD_HASH`         | 步骤 5 生成的密码哈希  | `v1:100000:...`              |
| `JWT_SECRET`            | 步骤 5 生成的 JWT 密钥 | `KF/+klyH...`                |
| `WORKER_URL`            | Worker 访问 URL        | `https://webdav.example.com` |
| `RATE_LIMIT_KV_ID`      | 限流 KV 命名空间 ID    | `0e0a3861...`                |
| `QUOTA_KV_ID`           | 配额 KV 命名空间 ID    | `105bd87c...`                |
| `TOTP_KV_ID`            | 2FA KV 命名空间 ID     | `8f6dbd72...`                |

可选配置（有默认值）：

| Secret 名称     | 说明                   | 默认值                |
| --------------- | ---------------------- | --------------------- |
| `MAX_FILE_SIZE` | 单文件最大大小（字节） | `104857600`（100MB）  |
| `STORAGE_QUOTA` | 总存储配额（字节）     | `10737418240`（10GB） |

#### 部署

配置完成后，部署会自动触发：

1. **自动部署**：
   - 每次 push 到 `main` 分支会自动部署
   - 可以在 Actions 标签页查看部署状态

2. **手动部署**：
   - 进入 Actions 标签页
   - 选择 "Deploy to Cloudflare Workers" workflow
   - 点击 "Run workflow"

3. **验证部署**：

   部署成功后，访问您的 Worker URL（如 `https://your-worker.workers.dev`）：

   ```bash
   # 测试连接
   curl https://your-worker.workers.dev/

   # 测试登录
   curl -X POST https://your-worker.workers.dev/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"your-password"}'
   ```

**详细部署文档**：

- 🇨🇳 [中文部署指南](docs/DEPLOYMENT_CN.md) - 包含图文说明和故障排查
- 🇬🇧 [English Deployment Guide](docs/DEPLOYMENT.md)

## 使用指南

### Web 界面使用

最简单的使用方式是通过浏览器访问。

#### 登录

1. 在浏览器中访问您的 Worker URL（如 `https://your-worker.workers.dev`）
2. 自动跳转到登录页面
3. 输入用户名和密码
4. 如果启用了 2FA，输入验证码
5. 或者点击"使用 Passkey 登录"进行无密码登录

#### 文件管理

登录后，您可以：

- **浏览文件**：点击文件夹进入，点击文件下载
- **上传文件**：
  - 点击"上传文件"按钮选择文件
  - 或直接拖拽文件到页面上
- **创建文件夹**：点击"新建文件夹"按钮
- **删除文件**：点击文件旁的删除按钮
- **搜索文件**：使用顶部搜索框过滤文件
- **切换视图**：网格视图和列表视图切换

#### 界面功能

- **多语言**：支持中文和英文切换
- **主题切换**：浅色、深色、跟随系统
- **文件图标**：自动识别文件类型显示对应图标
- **拖拽上传**：支持批量上传

### WebDAV 客户端连接

WebDAV 协议支持让您可以像访问本地磁盘一样管理云端文件。

#### 基本连接信息

```
服务器地址: https://your-worker.workers.dev/webdav/
用户名: 您配置的用户名
密码: 您配置的密码
```

**重要提示**：URL 必须以 `/webdav/` 结尾。

#### Windows 系统

**方式 1：使用资源管理器（内置）**

1. 打开"此电脑"
2. 右键空白处 → "添加一个网络位置"
3. 下一步 → 选择"选择自定义网络位置"
4. 输入地址：`https://your-worker.workers.dev/webdav/`
5. 输入用户名和密码
6. 完成后可以像访问本地文件夹一样使用

**方式 2：使用 RaiDrive（推荐）**

1. 下载安装 [RaiDrive](https://www.raidrive.com/)
2. 添加 → 选择 WebDAV
3. 填写：
   - 地址：`https://your-worker.workers.dev/webdav/`
   - 用户名和密码
4. 连接后会显示为本地磁盘

#### macOS 系统

**使用 Finder（内置）**

1. 打开 Finder
2. 菜单栏：前往 → 连接服务器（或按 ⌘K）
3. 输入地址：`https://your-worker.workers.dev/webdav/`
4. 点击"连接"
5. 输入用户名和密码
6. 连接后显示在边栏"位置"中

#### Linux 系统

**GNOME（Ubuntu 等）**

1. 打开文件管理器（Nautilus）
2. 左侧 → "其他位置"
3. 底部"连接到服务器"输入：`davs://your-worker.workers.dev/webdav/`
4. 输入用户名和密码
5. 连接后显示在侧边栏

**KDE（Kubuntu 等）**

1. 打开文件管理器（Dolphin）
2. 地址栏输入：`webdavs://your-worker.workers.dev/webdav/`
3. 输入用户名和密码

#### 移动设备

**iOS（iPhone/iPad）**

推荐使用 [Documents by Readdle](https://apps.apple.com/app/documents/id364901807)：

1. 安装 Documents App
2. 右下角 → 添加连接 → WebDAV 服务器
3. 填写连接信息
4. 可以直接查看、编辑、分享文件

**Android**

推荐使用 [Solid Explorer](https://play.google.com/store/apps/details?id=pl.solidexplorer2)：

1. 安装 Solid Explorer
2. 右上角菜单 → 存储管理器 → 添加云存储
3. 选择 WebDAV
4. 填写连接信息

#### 使用 2FA 的 WebDAV 连接

如果您启用了双因素认证，WebDAV 客户端需要特殊配置：

**方式 1：使用应用密码（App Password）**

某些客户端支持在密码字段附加 2FA 验证码：

```
密码: 您的密码123456
```

其中 `123456` 是当前的 TOTP 验证码（6位数字）。

**方式 2：使用 Bearer Token（高级）**

1. 先通过 API 获取访问令牌：

   ```bash
   # 登录获取令牌
   curl -X POST https://your-worker.workers.dev/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"your-password"}'

   # 如果需要 2FA，会返回 partialToken，然后验证：
   curl -X POST https://your-worker.workers.dev/auth/2fa/verify \
     -H "Content-Type: application/json" \
     -d '{"partialToken":"PARTIAL_TOKEN","code":"123456"}'
   ```

2. 使用返回的 `accessToken` 作为密码（部分客户端支持）

### 安全功能设置

#### 启用双因素认证（2FA）

1. **准备工作**：
   - 在手机上安装验证器 App（推荐：Google Authenticator、Authy、Microsoft Authenticator）

2. **开启 2FA**：

   ```bash
   # 发起设置请求（需要先登录获取 accessToken）
   curl -X POST https://your-worker.workers.dev/auth/2fa/setup \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
   ```

   返回：

   ```json
   {
     "secret": "JBSWY3DPEHPK3PXP",
     "qrCodeUrl": "otpauth://totp/CFr2-WebDAV:admin?secret=...",
     "recoveryCodes": ["A3B2C-5D7F1", "F1E8D-9A42B", ...]
   }
   ```

3. **添加到验证器 App**：
   - 打开验证器 App
   - 扫描 QR 码（使用 `qrCodeUrl` 生成）
   - 或手动输入 `secret`

4. **验证并启用**：

   ```bash
   # 输入验证器显示的 6 位数字
   curl -X POST https://your-worker.workers.dev/auth/2fa/verify-setup \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"code":"123456"}'
   ```

5. **保存恢复码**：
   - 将 `recoveryCodes` 打印或保存到安全位置
   - 每个恢复码只能使用一次
   - 丢失手机时可用恢复码登录

#### 设置 Passkey 无密码登录

**前提条件**：

- 使用支持 WebAuthn 的现代浏览器（Chrome 67+、Firefox 60+、Safari 13+、Edge 18+）
- 设备支持生物识别（Touch ID、Face ID、Windows Hello）或拥有 FIDO2 安全密钥

**步骤**：

1. **登录 Web 界面**（使用密码或密码+2FA）

2. **注册 Passkey**：
   - 在 Web 界面中找到"安全设置"或"Passkey 管理"
   - 点击"添加 Passkey"
   - 浏览器会提示选择认证方式：
     - "使用此设备"（生物识别）
     - "USB 安全密钥"
     - "iPhone/iPad/Android 手机"（跨设备）
   - 按提示完成认证
   - 给 Passkey 起个名字（如"我的 iPhone"）

3. **测试 Passkey 登录**：
   - 退出登录
   - 在登录页面点击"使用 Passkey 登录"
   - 输入用户名
   - 使用生物识别或安全密钥验证
   - 无需输入密码即可登录

4. **管理 Passkey**：
   - 可以注册多个 Passkey（不同设备）
   - 在 Web 界面查看所有已注册的 Passkey
   - 可以删除不再使用的 Passkey

**API 方式注册**（高级用户）：

详细的 API 调用流程请参考 [安全功能设置指南](docs/SECURITY_SETUP.md#stage-3-webauthn-passkeys-)。

#### 关闭 2FA

如果需要关闭双因素认证：

```bash
curl -X POST https://your-worker.workers.dev/auth/2fa/disable \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password":"your-password"}'
```

**警告**：关闭 2FA 会降低账户安全性。

#### 重新生成恢复码

如果恢复码用完或丢失：

```bash
curl -X POST https://your-worker.workers.dev/auth/2fa/recovery-codes/regenerate \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password":"your-password"}'
```

**完整安全设置文档**：[安全功能设置指南](docs/SECURITY_SETUP.md)

## 常见问题

### 部署相关

<details>
<summary><strong>Q: 部署后无法访问，显示 404 或 500 错误？</strong></summary>

**可能原因**：

1. Worker 部署未成功
2. R2 存储桶名称配置错误
3. KV 命名空间 ID 不正确

**解决方法**：

1. 检查 GitHub Actions 部署日志，确认部署成功
2. 在 Cloudflare Dashboard 中验证：
   - Workers & Pages → 找到您的 Worker → 查看是否部署成功
   - R2 → 确认存储桶存在且名称与配置一致
   - KV → 确认三个命名空间都已创建
3. 检查 wrangler.toml 或 GitHub Secrets 中的配置是否正确

</details>

<details>
<summary><strong>Q: 如何更新 Worker URL？</strong></summary>

部署后需要更新 `WORKER_URL` 配置：

1. 获取实际的 Worker URL（在 Cloudflare Dashboard 或部署日志中）
2. **如果使用一键部署**：
   - 在 Cloudflare Dashboard → Workers → 您的 Worker → Settings → Variables
   - 修改 `WORKER_URL` 环境变量

3. **如果使用 GitHub Actions**：
   - 更新 GitHub Secret `WORKER_URL`
   - 重新运行部署 workflow

</details>

<details>
<summary><strong>Q: 可以绑定自定义域名吗？</strong></summary>

可以。在 Cloudflare Dashboard 中：

1. Workers & Pages → 您的 Worker → Settings → Triggers
2. Custom Domains → Add Custom Domain
3. 输入您的域名（需要在 Cloudflare 托管）
4. 更新 `WORKER_URL` 环境变量为新域名

</details>

### 使用相关

<details>
<summary><strong>Q: Windows 文件资源管理器连接 WebDAV 失败？</strong></summary>

Windows 默认不支持非 HTTPS 的 WebDAV，并且对某些配置敏感。

**解决方法**：

1. 确保使用 HTTPS（Cloudflare Workers 默认提供）
2. URL 必须以 `/webdav/` 结尾
3. 推荐使用 RaiDrive 或 Cyberduck 代替系统自带功能
4. 如果必须使用系统自带，确保：
   - 启用了 WebClient 服务
   - 注册表中允许基本认证（仅用于测试）

</details>

<details>
<summary><strong>Q: 上传大文件失败？</strong></summary>

**原因**：

- 超过配置的单文件大小限制（默认 100MB）
- Cloudflare Workers 请求时间限制（免费版 30 秒，付费版 15 分钟）

**解决方法**：

1. 调整 `MAX_FILE_SIZE` 环境变量
2. 对于大文件（> 100MB）：
   - 考虑使用 Cloudflare Workers Paid Plan
   - 或使用支持分块上传的客户端
3. 分批上传多个小文件

</details>

<details>
<summary><strong>Q: 如何增加存储配额？</strong></summary>

默认配额为 10GB，可以调整：

1. 修改 `STORAGE_QUOTA` 环境变量（单位：字节）
2. 例如设置为 50GB：`STORAGE_QUOTA=53687091200`
3. 注意 Cloudflare R2 的免费额度限制：
   - 存储：10 GB/月（免费）
   - Class A 操作：100 万次/月（免费）
   - Class B 操作：1000 万次/月（免费）

</details>

<details>
<summary><strong>Q: 忘记密码怎么办？</strong></summary>

需要重新生成密码哈希并更新配置：

1. 使用[部署步骤](#方式-2github-actions-自动部署推荐)中的命令生成新的 `PASSWORD_HASH`
2. 更新环境变量：
   - **一键部署**：在 Cloudflare Dashboard 中更新
   - **GitHub Actions**：更新 GitHub Secret 并重新部署
3. 新密码立即生效

</details>

### 安全相关

<details>
<summary><strong>Q: 丢失了 2FA 验证器，无法登录？</strong></summary>

使用恢复码登录：

1. 在登录页面输入用户名和密码
2. 2FA 验证码处输入恢复码（如 `A3B2C-5D7F1`）
3. 登录后建议：
   - 关闭旧的 2FA 配置
   - 重新设置 2FA
   - 保存新的恢复码

如果恢复码也丢失，只能通过重置 KV 命名空间清除 2FA 配置（会丢失所有 2FA 和 Passkey 数据）。

</details>

<details>
<summary><strong>Q: Passkey 登录失败？</strong></summary>

**可能原因**：

1. 浏览器不支持 WebAuthn
2. 使用了不同的域名（Passkey 绑定域名）
3. 设备或浏览器未注册 Passkey

**解决方法**：

1. 确认浏览器支持 WebAuthn（查看 [Can I Use](https://caniuse.com/webauthn)）
2. 确保访问的域名与注册 Passkey 时相同
3. 如果 Passkey 不可用，使用密码登录
4. 重新注册新的 Passkey

</details>

<details>
<summary><strong>Q: 如何查看登录日志和可疑活动？</strong></summary>

在 Cloudflare Dashboard 中：

1. Workers & Pages → 您的 Worker → Logs
2. 选择 "Real-time Logs" 查看实时日志
3. 关注：
   - 失败的登录尝试
   - 被限流的 IP 地址
   - 2FA 验证失败

付费用户可以使用 Logpush 导出日志到外部系统进行分析。

</details>

### 性能相关

<details>
<summary><strong>Q: 文件下载速度慢？</strong></summary>

**可能原因**：

- 地理位置距离 R2 存储桶较远
- 网络问题

**优化方法**：

1. Cloudflare R2 自动使用全球边缘网络加速
2. 对于大文件，考虑：
   - 开启 Cloudflare CDN 缓存
   - 使用 R2 公共 URL（如果不需要认证）
3. 检查本地网络连接

</details>

<details>
<summary><strong>Q: Worker 请求超时？</strong></summary>

免费版 Cloudflare Workers 有 30 秒 CPU 时间限制。

**解决方法**：

1. 减小单次操作的文件大小
2. 升级到 Workers Paid Plan（CPU 时间限制提升到 15 分钟）
3. 对于列表大量文件，使用分页

</details>

### 其他问题

<details>
<summary><strong>Q: 可以多人使用吗？</strong></summary>

当前版本仅支持单用户（一个用户名/密码）。

如需多用户支持：

- 可以为每个用户部署独立的 Worker 实例
- 或考虑 Fork 项目并实现多用户功能

</details>

<details>
<summary><strong>Q: 数据安全吗？会被 Cloudflare 访问吗？</strong></summary>

**数据安全保障**：

1. 密码使用 PBKDF2 哈希存储，即使数据库泄露也无法还原原密码
2. JWT 令牌使用 HMAC-SHA256 签名，无法伪造
3. 所有传输使用 HTTPS 加密

**Cloudflare 访问**：

- Cloudflare 作为基础设施提供商，理论上可以访问存储在 R2 的数据
- 但 Cloudflare 的隐私政策承诺不会查看用户数据
- 如果需要端到端加密，建议上传前在客户端加密文件

</details>

<details>
<summary><strong>Q: 如何备份数据？</strong></summary>

**方式 1：使用 WebDAV 客户端**

- 连接到 WebDAV
- 复制所有文件到本地

**方式 2：使用 Cloudflare API**

```bash
# 使用 rclone 同步 R2 数据
rclone sync r2:my-bucket /local/backup
```

**方式 3：R2 快照**（付费功能）

- Cloudflare R2 支持对象版本控制（需要在桶设置中启用）

建议定期备份重要数据。

</details>

## 本地开发

如果您需要修改代码或本地测试：

### 环境要求

- Node.js 18+
- npm 或 pnpm
- Cloudflare 账户（用于本地开发时连接 R2 和 KV）

### 开发步骤

1. **克隆仓库**：

   ```bash
   git clone https://github.com/amm10090/CFr2-webdav.git
   cd CFr2-webdav
   ```

2. **安装依赖**：

   ```bash
   npm install
   # 或
   pnpm install
   ```

3. **配置 wrangler.toml**：

   ```bash
   cp wrangler.toml.example wrangler.toml
   # 编辑 wrangler.toml，填入您的配置
   ```

4. **本地开发**：

   ```bash
   npm run dev
   ```

   访问 `http://localhost:8787` 测试

5. **部署到 Cloudflare**：
   ```bash
   npm run deploy
   ```

### 注意事项

- 不要提交包含真实凭据的 `wrangler.toml` 到 Git
- 已在 `.gitignore` 中排除 `wrangler.toml`
- 本地开发使用 Cloudflare 的远程 R2 和 KV（需要配置绑定）

## 文档索引

### 部署文档

- [中文部署指南](docs/DEPLOYMENT_CN.md) - 详细的图文部署教程
- [English Deployment Guide](docs/DEPLOYMENT.md) - Full deployment instructions

### 安全文档

- [安全功能设置指南](docs/SECURITY_SETUP.md) - 2FA 和 Passkey 设置详解

### API 文档

- 认证 API：
  - `POST /auth/login` - 用户登录
  - `POST /auth/refresh` - 刷新令牌
  - `POST /auth/2fa/setup` - 设置 2FA
  - `POST /auth/2fa/verify` - 验证 2FA
  - `POST /auth/passkey/register/*` - Passkey 注册
  - `POST /auth/passkey/authenticate/*` - Passkey 认证
- WebDAV API：标准 WebDAV 协议（RFC 4918）

## 更新日志

### v1.0.0（当前版本）

- 完整的 WebDAV 协议支持
- 三阶段安全功能：基础安全、2FA、Passkey
- 现代化 Web UI（Tailwind CSS 4）
- 多语言和主题支持

## 贡献

欢迎提交 Pull Requests 或创建 Issues 来改进这个项目！

### 贡献指南

1. Fork 本仓库
2. 创建特性分支（`git checkout -b feature/AmazingFeature`）
3. 提交更改（`git commit -m 'Add some AmazingFeature'`）
4. 推送到分支（`git push origin feature/AmazingFeature`）
5. 开启 Pull Request

## 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

## 致谢

本项目基于以下技术构建：

- **Cloudflare Workers** - 无服务器边缘计算平台
- **Cloudflare R2** - 兼容 S3 的对象存储
- **Cloudflare KV** - 全球分布式键值存储
- **WebAuthn** - W3C Web Authentication API 标准
- **TOTP** - RFC 6238 Time-based One-Time Password 算法
- **Tailwind CSS** - 实用优先的 CSS 框架

特别感谢所有贡献者和使用本项目的用户！

---

**安全提醒**：

1. 定期更新密码和轮换 JWT 密钥
2. 启用 2FA 或 Passkey 以提高安全性
3. 不要在公共网络使用弱密码
4. 定期备份重要数据
5. 监控 Worker 日志以发现异常活动

如有任何问题，请[创建 Issue](https://github.com/amm10090/CFr2-webdav/issues) 或查看[讨论区](https://github.com/amm10090/CFr2-webdav/discussions)。
