# Cloudflare R2 WebDAV Server

这个项目实现了一个基于 Cloudflare Workers 和 R2 存储的 WebDAV 服务器。它允许用户通过 WebDAV 协议访问和管理存储在 Cloudflare R2 中的文件和目录。

## 特性

- 完全兼容 WebDAV 协议
- 基于 Cloudflare Workers，无需管理服务器
- 使用 Cloudflare R2 作为存储后端（免费额度慷慨）
- 支持基本的身份验证
- 支持文件上传、下载、删除、移动和复制操作
- 支持目录创建和列表

## 一键部署到 Cloudflare Workers

点击下面的按钮，一键将此项目部署到您的Cloudflare Workers账户：

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/amm10090/CFr2-webdav)

注需要有 Cloudflare 账户才能使用此功能。如果您还没有账户，可以在 [Cloudflare 官网](https://www.cloudflare.com) 注册。

## 手动部署步骤 [Githut Actions]

如果您需要自定义配置或想要深入了解部署流程，请按以下步骤操作：

### 前提条件

- Cloudflare 账户（需有目标 Account ID）
- 已创建的 R2 存储桶
- GitHub 账户
- （可选）若想在前端开启“演示模式”按钮，请设置环境变量 `DEMO_MODE=true`（默认关闭）

### 步骤 1: 准备 Cloudflare 凭据

1. 进入 Cloudflare 仪表盘 → **My Profile → API Tokens → Create Token**，选择模板 **“Edit Cloudflare Workers”**，并确认勾选/包含下列最小权限：
   - User / Memberships: Read
   - Account / Workers Scripts: Edit
   - Account / Workers R2 Storage: Edit
   - （可选）Account / Workers KV Storage: Edit（Wrangler 常用）
   - （若使用自定义路由）Zone / Workers Routes: Edit
2. 选择正确的 **Account**（与 `CLOUDFLARE_ACCOUNT_ID` 一致），生成 **用户 API Token**（不要用 Account Token）。
3. 记下：`CLOUDFLARE_API_TOKEN` 和 `CLOUDFLARE_ACCOUNT_ID`，以及 R2 的 `BUCKET_NAME`。
4. 验证 Token 权限（可选但推荐）：
   ```bash
   curl -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        https://api.cloudflare.com/client/v4/user/tokens/verify
   # 返回 result.status=="active" 且 scopes 中含上述权限即通过
   ```

### 步骤 2: 准备仓库

Fork 这个仓库到您的 GitHub 账户。

```
https://github.com/amm10090/CFr2-webdav.git
```

### 步骤 3: 配置 GitHub Secrets

在仓库 Settings → Secrets and variables → Actions 中添加：

- `CLOUDFLARE_API_TOKEN`（必填，上述用户 API Token）
- `CLOUDFLARE_ACCOUNT_ID`（必填，与 Token 账户一致）
- `BUCKET_NAME`（必填，目标 R2 桶名）
- `USERNAME`（可选，默认 `_user`）
- `PASSWORD`（可选，默认 `_pass`）
- `DEMO_MODE`（可选，设为 `true` 时在前端显示“演示模式”入口；默认不显示）

### 步骤 4: 配置 GitHub Actions

1. 在您的 GitHub 仓库设置中，启用 GitHub Actions。
2. workflow 文件已经存在，请选择： .github/workflow/main.yml

### 步骤 4: 触发部署

完成 Secrets 配置后，推送到 `main` 或在 Actions 页面手动 “Re-run jobs”，workflow 会：

- 校验 `CLOUDFLARE_API_TOKEN` 与 `CLOUDFLARE_ACCOUNT_ID`
- 生成 `wrangler.toml`
- 使用 Wrangler 4.53.0 部署到 Cloudflare Workers

您可以在 GitHub 仓库的 Actions 标签页中查看部署进度。部署成功后，您可以在 Cloudflare Workers 仪表板中找到您的 Worker URL。

## 使用方法

使用任何支持 WebDAV 协议的客到您的 Worker URL，使用配置的用户名和密码进行身份验证。

## 本地开发（可选）

如果您需要在本地进行开发和测试，请按以下步骤操作：

0. 同上面步骤1 ：配置 Cloudflare

1. 克隆仓库到本地：

   ```bash
   git clone https://github.com/amm10090/CFr2-webdav.git
   cd cf-r2-webdav
   ```

2. 安装依赖：

   ```bash
   npm install
   ```

3. 修改wrangler.toml.template为wrangler.toml文件，并修改为你的实际参数：

4. 使用 Wrangler 进行本地开发：
   ```bash
   npx wrangler dev --local
   ```

注意：本地开发可能无法完全模拟 Cloudflare Workers 环境，特别是 R2 存储的操作。

## 注意事项

- 确保妥善保管您的 API 令牌和其他敏感信息。
- 定期更新您的依赖以确保安全性。
- 遵守 Cloudflare 的使用政策和条款。

## 贡献

欢迎提交 Pull Requests 或创建 Issues 来改进这个项目。

## 许可证

本项目采用 MIT 许可证。
