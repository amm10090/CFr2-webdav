# Cloudflare R2 WebDAV Server

English | [简体中文](README.md)

Enterprise-grade WebDAV server built on Cloudflare Workers and R2 Storage, with comprehensive file management and multi-layer security authentication.

## Table of Contents

- [Features](#features)
- [Security](#security)
- [Quick Deployment](#quick-deployment)
- [Usage Guide](#usage-guide)
- [FAQ](#faq)
- [Local Development](#local-development)
- [Documentation](#documentation)

## Features

### File Management

- Fully compatible with WebDAV protocol, supports all standard clients
- File upload, download, delete, move, and copy operations
- Directory creation and browsing
- Modern built-in Web file management interface

### Technical Architecture

- Built on Cloudflare Workers edge computing for global accelerated access
- Uses Cloudflare R2 as storage backend (generous free tier)
- Serverless, automatic scaling
- Customizable storage quotas and file size limits

## Security

This project implements an enterprise-grade three-tier security system. You can choose to enable features based on your needs.

### Basic Security (Required)

- **Encrypted Password Storage** - PBKDF2 hashing with 100,000 iterations
- **JWT Token Authentication** - Access tokens (15 min) + Refresh tokens (7 days)
- **Brute Force Protection** - Three-dimensional rate limiting (IP/User/Combo), banned after 5 failures
- **File Security Validation** - Extension whitelist + MIME type checking
- **Storage Quota Management** - Default 10GB total, 100MB per file

### Two-Factor Authentication (Optional)

- **TOTP Dynamic Codes** - Compatible with Google Authenticator and other standard apps
- **Recovery Code Backup** - 10 one-time-use recovery keys
- **WebDAV Integration** - Desktop clients support passing codes via custom headers
- **Mandatory Enforcement** - Once enabled, 2FA required for all login methods

### Passkey Passwordless Login (Optional)

- **Biometric Authentication** - Touch ID, Face ID, Windows Hello
- **Hardware Keys** - YubiKey, Titan Key, and other FIDO2 security keys
- **Phishing-Resistant** - Credentials bound to your domain, unusable on fake sites
- **Multi-Device Support** - Register multiple authenticators
- **WebAuthn Standard** - Compliant with W3C Web Authentication API

For detailed security configuration, see [Security Setup Guide](docs/SECURITY_SETUP.md).

## Quick Deployment

Choose one deployment method to get started:

### Method 1: One-Click Deploy (Easiest)

Ideal for quick trials and personal use.

1. Click the button below to start deployment:

   [![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/amm10090/CFr2-webdav)

2. Follow the on-screen prompts to complete deployment
3. See [Security Setup Guide](docs/SECURITY_SETUP.md) to configure password and security features

**Note**: Requires a Cloudflare account. If you don't have one, register for free at [Cloudflare](https://www.cloudflare.com).

### Method 2: GitHub Actions Auto-Deploy (Recommended)

Ideal for version control and team collaboration scenarios.

#### Prerequisites

1. **Fork this repository** to your GitHub account
2. **Create a Cloudflare account** (if you don't have one)
3. **Create an R2 bucket**:
   - Log in to Cloudflare Dashboard
   - Go to R2 → Create bucket
   - Enter bucket name (e.g., `my-webdav-storage`)

4. **Create KV namespaces** (for storing authentication and rate limiting data):

   Use Wrangler CLI or create in Cloudflare Dashboard:

   ```bash
   # Using Wrangler CLI (recommended)
   npx wrangler kv:namespace create "RATE_LIMIT_KV"
   npx wrangler kv:namespace create "QUOTA_KV"
   npx wrangler kv:namespace create "TOTP_KV"
   ```

   Record each namespace ID for later configuration in GitHub Secrets.

5. **Generate password hash and JWT secret**:

   ```bash
   # Clone repository locally
   git clone https://github.com/your-username/CFr2-webdav.git
   cd CFr2-webdav

   # Install dependencies
   npm install

   # Generate password hash (replace your-password with your password)
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

   # Generate JWT secret
   node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(32).toString('base64'));"
   ```

6. **Get Cloudflare API Token**:
   - Visit [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)
   - Click "Create Token"
   - Use "Edit Cloudflare Workers" template
   - Permissions:
     - Account → Cloudflare Workers Scripts → Edit
     - Account → Account Settings → Read
   - Copy token after creation (shown only once)

7. **Get Cloudflare Account ID**:
   - Log in to Cloudflare Dashboard
   - Find Account ID in the right sidebar

#### Configure GitHub Secrets

In your forked repository: **Settings → Secrets and variables → Actions → New repository secret**

Add the following Secrets (all required):

| Secret Name             | Description                | Example                      |
| ----------------------- | -------------------------- | ---------------------------- |
| `CLOUDFLARE_API_TOKEN`  | API Token                  | `abc123...`                  |
| `CLOUDFLARE_ACCOUNT_ID` | Account ID                 | `1234567890abcdef...`        |
| `BUCKET_NAME`           | R2 bucket name             | `my-webdav-storage`          |
| `USERNAME`              | Admin username             | `admin`                      |
| `PASSWORD_HASH`         | Password hash from step 5  | `v1:100000:...`              |
| `JWT_SECRET`            | JWT secret from step 5     | `KF/+klyH...`                |
| `WORKER_URL`            | Worker access URL          | `https://webdav.example.com` |
| `RATE_LIMIT_KV_ID`      | Rate limit KV namespace ID | `0e0a3861...`                |
| `QUOTA_KV_ID`           | Quota KV namespace ID      | `105bd87c...`                |
| `TOTP_KV_ID`            | 2FA KV namespace ID        | `8f6dbd72...`                |

Optional configuration (with defaults):

| Secret Name     | Description                  | Default              |
| --------------- | ---------------------------- | -------------------- |
| `MAX_FILE_SIZE` | Max file size in bytes       | `104857600` (100MB)  |
| `STORAGE_QUOTA` | Total storage quota in bytes | `10737418240` (10GB) |

#### Deploy

After configuration, deployment will trigger automatically:

1. **Automatic deployment**:
   - Deploys automatically on every push to `main` branch
   - Check deployment status in Actions tab

2. **Manual deployment**:
   - Go to Actions tab
   - Select "Deploy to Cloudflare Workers" workflow
   - Click "Run workflow"

3. **Verify deployment**:

   After successful deployment, visit your Worker URL (e.g., `https://your-worker.workers.dev`):

   ```bash
   # Test connection
   curl https://your-worker.workers.dev/

   # Test login
   curl -X POST https://your-worker.workers.dev/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"your-password"}'
   ```

**Detailed deployment documentation**:

- 🇨🇳 [Chinese Deployment Guide](docs/DEPLOYMENT_CN.md)
- 🇬🇧 [English Deployment Guide](docs/DEPLOYMENT.md) - With illustrations and troubleshooting

## Usage Guide

### Web Interface

The simplest way to use the service is through a browser.

#### Login

1. Visit your Worker URL in a browser (e.g., `https://your-worker.workers.dev`)
2. Automatically redirects to login page
3. Enter username and password
4. If 2FA is enabled, enter verification code
5. Or click "Login with Passkey" for passwordless login

#### File Management

After login, you can:

- **Browse files**: Click folders to enter, click files to download
- **Upload files**:
  - Click "Upload File" button to select files
  - Or drag and drop files onto the page
- **Create folders**: Click "New Folder" button
- **Delete files**: Click delete button next to files
- **Search files**: Use search box at the top to filter files
- **Switch views**: Toggle between grid and list view

#### Interface Features

- **Multi-language**: Switch between Chinese and English
- **Theme switching**: Light, dark, or follow system
- **File icons**: Auto-detect file types and display corresponding icons
- **Drag & drop upload**: Support batch upload

### WebDAV Client Connection

WebDAV protocol support lets you manage cloud files like a local disk.

#### Basic Connection Info

```
Server Address: https://your-worker.workers.dev/webdav/
Username: Your configured username
Password: Your configured password
```

**Important**: URL must end with `/webdav/`.

#### Windows

**Method 1: File Explorer (Built-in)**

1. Open "This PC"
2. Right-click blank area → "Add a network location"
3. Next → Select "Choose a custom network location"
4. Enter address: `https://your-worker.workers.dev/webdav/`
5. Enter username and password
6. After completion, use like a local folder

**Method 2: RaiDrive (Recommended)**

1. Download and install [RaiDrive](https://www.raidrive.com/)
2. Add → Select WebDAV
3. Fill in:
   - Address: `https://your-worker.workers.dev/webdav/`
   - Username and password
4. After connection, appears as local disk

#### macOS

**Using Finder (Built-in)**

1. Open Finder
2. Menu bar: Go → Connect to Server (or press ⌘K)
3. Enter address: `https://your-worker.workers.dev/webdav/`
4. Click "Connect"
5. Enter username and password
6. After connection, appears in sidebar under "Locations"

#### Linux

**GNOME (Ubuntu, etc.)**

1. Open file manager (Nautilus)
2. Left sidebar → "Other Locations"
3. At bottom "Connect to Server" enter: `davs://your-worker.workers.dev/webdav/`
4. Enter username and password
5. After connection, appears in sidebar

**KDE (Kubuntu, etc.)**

1. Open file manager (Dolphin)
2. In address bar enter: `webdavs://your-worker.workers.dev/webdav/`
3. Enter username and password

#### Mobile Devices

**iOS (iPhone/iPad)**

Recommended: [Documents by Readdle](https://apps.apple.com/app/documents/id364901807)

1. Install Documents App
2. Bottom right → Add Connection → WebDAV Server
3. Fill in connection info
4. Can view, edit, and share files directly

**Android**

Recommended: [Solid Explorer](https://play.google.com/store/apps/details?id=pl.solidexplorer2)

1. Install Solid Explorer
2. Top right menu → Storage Manager → Add Cloud Storage
3. Select WebDAV
4. Fill in connection info

#### WebDAV Connection with 2FA

If you've enabled two-factor authentication, WebDAV clients need special configuration:

**Method 1: App Password**

Some clients support appending the 2FA code to the password field:

```
Password: your-password123456
```

Where `123456` is the current TOTP code (6 digits).

**Method 2: Bearer Token (Advanced)**

1. First obtain access token via API:

   ```bash
   # Login to get token
   curl -X POST https://your-worker.workers.dev/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"your-password"}'

   # If 2FA is needed, returns partialToken, then verify:
   curl -X POST https://your-worker.workers.dev/auth/2fa/verify \
     -H "Content-Type: application/json" \
     -d '{"partialToken":"PARTIAL_TOKEN","code":"123456"}'
   ```

2. Use returned `accessToken` as password (some clients support this)

### Security Features Setup

#### Enable Two-Factor Authentication (2FA)

1. **Preparation**:
   - Install authenticator app on your phone (recommended: Google Authenticator, Authy, Microsoft Authenticator)

2. **Enable 2FA**:

   ```bash
   # Initiate setup request (requires login to get accessToken first)
   curl -X POST https://your-worker.workers.dev/auth/2fa/setup \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
   ```

   Returns:

   ```json
   {
     "secret": "JBSWY3DPEHPK3PXP",
     "qrCodeUrl": "otpauth://totp/CFr2-WebDAV:admin?secret=...",
     "recoveryCodes": ["A3B2C-5D7F1", "F1E8D-9A42B", ...]
   }
   ```

3. **Add to authenticator app**:
   - Open authenticator app
   - Scan QR code (generate using `qrCodeUrl`)
   - Or manually enter `secret`

4. **Verify and enable**:

   ```bash
   # Enter 6-digit code displayed by authenticator
   curl -X POST https://your-worker.workers.dev/auth/2fa/verify-setup \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"code":"123456"}'
   ```

5. **Save recovery codes**:
   - Print or save `recoveryCodes` in a secure location
   - Each recovery code can only be used once
   - Use recovery codes to login if you lose your phone

#### Setup Passkey Passwordless Login

**Prerequisites**:

- Modern browser with WebAuthn support (Chrome 67+, Firefox 60+, Safari 13+, Edge 18+)
- Device with biometric support (Touch ID, Face ID, Windows Hello) or FIDO2 security key

**Steps**:

1. **Login to Web interface** (using password or password+2FA)

2. **Register Passkey**:
   - Find "Security Settings" or "Passkey Management" in Web interface
   - Click "Add Passkey"
   - Browser prompts to choose authentication method:
     - "This device" (biometric)
     - "USB security key"
     - "iPhone/iPad/Android phone" (cross-device)
   - Complete authentication as prompted
   - Give your Passkey a name (e.g., "My iPhone")

3. **Test Passkey login**:
   - Log out
   - On login page, click "Login with Passkey"
   - Enter username
   - Verify with biometric or security key
   - Login without entering password

4. **Manage Passkeys**:
   - Can register multiple Passkeys (different devices)
   - View all registered Passkeys in Web interface
   - Can delete Passkeys no longer in use

**API Method Registration** (Advanced users):

See [Security Setup Guide](docs/SECURITY_SETUP.md#stage-3-webauthn-passkeys-) for detailed API call flow.

#### Disable 2FA

If you need to disable two-factor authentication:

```bash
curl -X POST https://your-worker.workers.dev/auth/2fa/disable \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password":"your-password"}'
```

**Warning**: Disabling 2FA reduces account security.

#### Regenerate Recovery Codes

If recovery codes are used up or lost:

```bash
curl -X POST https://your-worker.workers.dev/auth/2fa/recovery-codes/regenerate \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password":"your-password"}'
```

**Complete security setup documentation**: [Security Setup Guide](docs/SECURITY_SETUP.md)

## FAQ

### Deployment

<details>
<summary><strong>Q: Can't access after deployment, showing 404 or 500 error?</strong></summary>

**Possible causes**:

1. Worker deployment failed
2. R2 bucket name configured incorrectly
3. KV namespace IDs incorrect

**Solutions**:

1. Check GitHub Actions deployment logs to confirm successful deployment
2. Verify in Cloudflare Dashboard:
   - Workers & Pages → Find your Worker → Check if deployed successfully
   - R2 → Confirm bucket exists and name matches configuration
   - KV → Confirm all three namespaces created
3. Check if configuration in wrangler.toml or GitHub Secrets is correct

</details>

<details>
<summary><strong>Q: How to update Worker URL?</strong></summary>

After deployment, need to update `WORKER_URL` configuration:

1. Get actual Worker URL (in Cloudflare Dashboard or deployment logs)
2. **If using one-click deploy**:
   - In Cloudflare Dashboard → Workers → Your Worker → Settings → Variables
   - Modify `WORKER_URL` environment variable

3. **If using GitHub Actions**:
   - Update GitHub Secret `WORKER_URL`
   - Re-run deployment workflow

</details>

<details>
<summary><strong>Q: Can I bind a custom domain?</strong></summary>

Yes. In Cloudflare Dashboard:

1. Workers & Pages → Your Worker → Settings → Triggers
2. Custom Domains → Add Custom Domain
3. Enter your domain (must be hosted on Cloudflare)
4. Update `WORKER_URL` environment variable to new domain

</details>

### Usage

<details>
<summary><strong>Q: Windows File Explorer fails to connect to WebDAV?</strong></summary>

Windows doesn't support non-HTTPS WebDAV by default and is sensitive to certain configurations.

**Solutions**:

1. Ensure using HTTPS (Cloudflare Workers provides by default)
2. URL must end with `/webdav/`
3. Recommend using RaiDrive or Cyberduck instead of built-in functionality
4. If must use built-in:
   - Enable WebClient service
   - Allow basic authentication in registry (testing only)

</details>

<details>
<summary><strong>Q: Large file upload fails?</strong></summary>

**Reasons**:

- Exceeds configured single file size limit (default 100MB)
- Cloudflare Workers request time limit (free tier 30 seconds, paid tier 15 minutes)

**Solutions**:

1. Adjust `MAX_FILE_SIZE` environment variable
2. For large files (> 100MB):
   - Consider using Cloudflare Workers Paid Plan
   - Or use clients that support chunked upload
3. Upload multiple small files in batches

</details>

<details>
<summary><strong>Q: How to increase storage quota?</strong></summary>

Default quota is 10GB, can be adjusted:

1. Modify `STORAGE_QUOTA` environment variable (unit: bytes)
2. For example, set to 50GB: `STORAGE_QUOTA=53687091200`
3. Note Cloudflare R2 free tier limits:
   - Storage: 10 GB/month (free)
   - Class A operations: 1 million/month (free)
   - Class B operations: 10 million/month (free)

</details>

<details>
<summary><strong>Q: Forgot password?</strong></summary>

Need to regenerate password hash and update configuration:

1. Use commands in [deployment steps](#method-2-github-actions-auto-deploy-recommended) to generate new `PASSWORD_HASH`
2. Update environment variable:
   - **One-click deploy**: Update in Cloudflare Dashboard
   - **GitHub Actions**: Update GitHub Secret and redeploy
3. New password takes effect immediately

</details>

### Security

<details>
<summary><strong>Q: Lost 2FA authenticator, can't login?</strong></summary>

Use recovery code to login:

1. On login page, enter username and password
2. At 2FA code prompt, enter recovery code (e.g., `A3B2C-5D7F1`)
3. After login, recommend:
   - Disable old 2FA configuration
   - Re-setup 2FA
   - Save new recovery codes

If recovery codes also lost, can only reset KV namespace to clear 2FA configuration (will lose all 2FA and Passkey data).

</details>

<details>
<summary><strong>Q: Passkey login fails?</strong></summary>

**Possible causes**:

1. Browser doesn't support WebAuthn
2. Using different domain (Passkey bound to domain)
3. Device or browser doesn't have registered Passkey

**Solutions**:

1. Confirm browser supports WebAuthn (check [Can I Use](https://caniuse.com/webauthn))
2. Ensure accessing same domain as when Passkey was registered
3. If Passkey unavailable, use password login
4. Re-register new Passkey

</details>

<details>
<summary><strong>Q: How to view login logs and suspicious activity?</strong></summary>

In Cloudflare Dashboard:

1. Workers & Pages → Your Worker → Logs
2. Select "Real-time Logs" to view live logs
3. Pay attention to:
   - Failed login attempts
   - Rate-limited IP addresses
   - 2FA verification failures

Paid users can use Logpush to export logs to external systems for analysis.

</details>

### Performance

<details>
<summary><strong>Q: Slow file download speed?</strong></summary>

**Possible causes**:

- Geographic distance from R2 bucket is far
- Network issues

**Optimization methods**:

1. Cloudflare R2 automatically uses global edge network for acceleration
2. For large files, consider:
   - Enable Cloudflare CDN caching
   - Use R2 public URL (if authentication not needed)
3. Check local network connection

</details>

<details>
<summary><strong>Q: Worker request timeout?</strong></summary>

Free tier Cloudflare Workers has 30-second CPU time limit.

**Solutions**:

1. Reduce file size for single operations
2. Upgrade to Workers Paid Plan (CPU time limit increased to 15 minutes)
3. For listing many files, use pagination

</details>

### Other

<details>
<summary><strong>Q: Can multiple people use it?</strong></summary>

Current version only supports single user (one username/password).

For multi-user support:

- Deploy separate Worker instance for each user
- Or consider forking the project and implementing multi-user functionality

</details>

<details>
<summary><strong>Q: Is data secure? Can Cloudflare access it?</strong></summary>

**Data security guarantees**:

1. Passwords stored using PBKDF2 hash, even if database leaks, original password cannot be recovered
2. JWT tokens signed with HMAC-SHA256, cannot be forged
3. All transmissions use HTTPS encryption

**Cloudflare access**:

- Cloudflare as infrastructure provider theoretically can access data stored in R2
- But Cloudflare's privacy policy promises not to view user data
- If end-to-end encryption needed, recommend encrypting files on client before upload

</details>

<details>
<summary><strong>Q: How to backup data?</strong></summary>

**Method 1: Using WebDAV client**

- Connect to WebDAV
- Copy all files to local

**Method 2: Using Cloudflare API**

```bash
# Use rclone to sync R2 data
rclone sync r2:my-bucket /local/backup
```

**Method 3: R2 snapshots** (paid feature)

- Cloudflare R2 supports object versioning (need to enable in bucket settings)

Recommend backing up important data regularly.

</details>

## Local Development

If you need to modify code or test locally:

### Requirements

- Node.js 18+
- npm or pnpm
- Cloudflare account (for connecting to R2 and KV during local development)

### Development Steps

1. **Clone repository**:

   ```bash
   git clone https://github.com/amm10090/CFr2-webdav.git
   cd CFr2-webdav
   ```

2. **Install dependencies**:

   ```bash
   npm install
   # or
   pnpm install
   ```

3. **Configure wrangler.toml**:

   ```bash
   cp wrangler.toml.example wrangler.toml
   # Edit wrangler.toml, fill in your configuration
   ```

4. **Local development**:

   ```bash
   npm run dev
   ```

   Visit `http://localhost:8787` to test

5. **Deploy to Cloudflare**:
   ```bash
   npm run deploy
   ```

### Notes

- Don't commit `wrangler.toml` with real credentials to Git
- `wrangler.toml` already excluded in `.gitignore`
- Local development uses Cloudflare's remote R2 and KV (need to configure bindings)

## Documentation

### Deployment Docs

- [Chinese Deployment Guide](docs/DEPLOYMENT_CN.md) - Detailed illustrated tutorial
- [English Deployment Guide](docs/DEPLOYMENT.md) - Full deployment instructions

### Security Docs

- [Security Setup Guide](docs/SECURITY_SETUP.md) - 2FA and Passkey setup details

### API Docs

- Authentication API:
  - `POST /auth/login` - User login
  - `POST /auth/refresh` - Refresh token
  - `POST /auth/2fa/setup` - Setup 2FA
  - `POST /auth/2fa/verify` - Verify 2FA
  - `POST /auth/passkey/register/*` - Passkey registration
  - `POST /auth/passkey/authenticate/*` - Passkey authentication
- WebDAV API: Standard WebDAV protocol (RFC 4918)

## Changelog

### v1.0.0 (Current)

- Complete WebDAV protocol support
- Three-tier security: Basic security, 2FA, Passkey
- Modern Web UI (Tailwind CSS 4)
- Multi-language and theme support

## Contributing

Pull Requests and Issues are welcome to improve this project!

### Contribution Guide

1. Fork this repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

## Acknowledgments

This project is built with the following technologies:

- **Cloudflare Workers** - Serverless edge computing platform
- **Cloudflare R2** - S3-compatible object storage
- **Cloudflare KV** - Global distributed key-value storage
- **WebAuthn** - W3C Web Authentication API standard
- **TOTP** - RFC 6238 Time-based One-Time Password algorithm
- **Tailwind CSS** - Utility-first CSS framework

Special thanks to all contributors and users of this project!

---

**Security Reminders**:

1. Regularly update passwords and rotate JWT keys
2. Enable 2FA or Passkey to improve security
3. Don't use weak passwords on public networks
4. Regularly backup important data
5. Monitor Worker logs for unusual activity

For any questions, please [create an Issue](https://github.com/amm10090/CFr2-webdav/issues) or check [Discussions](https://github.com/amm10090/CFr2-webdav/discussions).
