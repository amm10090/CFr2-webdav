# CFr2-webdav Security Setup Guide

This guide will help you set up the Stage 1 security features for CFr2-webdav.

## Prerequisites

1. Cloudflare account with R2 enabled
2. `wrangler` CLI installed and configured
3. Node.js and npm installed

## Step 1: Create KV Namespaces

Create two KV namespaces for rate limiting and storage quota tracking:

```bash
# Create rate limiting KV namespace
wrangler kv:namespace create "RATE_LIMIT_KV"

# Create storage quota KV namespace
wrangler kv:namespace create "QUOTA_KV"
```

Save the namespace IDs from the output. You'll need them for Step 3.

## Step 2: Generate Password Hash

You have two options to generate a secure password hash:

### Option A: Using wrangler dev (Recommended)

1. Start development server:
```bash
npm run dev
```

2. In another terminal, run the hash generation script:
```bash
node scripts/generate-password-hash.js your-password-here
```

### Option B: Manual generation using Web Browser Console

1. Open browser console (F12)
2. Paste and run this code:

```javascript
async function generateHash(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    'raw',
    data,
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    key,
    256
  );

  const hashArray = new Uint8Array(derivedBits);
  const toBase64 = (arr) => btoa(String.fromCharCode(...arr));

  return `v1:100000:${toBase64(salt)}:${toBase64(hashArray)}`;
}

// Replace 'your-password-here' with your actual password
generateHash('your-password-here').then(console.log);
```

3. Copy the output hash

## Step 3: Generate JWT Secret

Generate a secure random JWT secret:

```bash
# Using OpenSSL
openssl rand -base64 32

# Or using Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

## Step 4: Configure Environment Variables

Update your `wrangler.toml` with the generated values:

```toml
[vars]
USERNAME = "admin"
PASSWORD_HASH = "v1:100000:YOUR_GENERATED_HASH_HERE"
JWT_SECRET = "YOUR_GENERATED_SECRET_HERE"
WORKER_URL = "https://your-worker.workers.dev"
BUCKET_NAME = "your-bucket-name"

# Optional: Customize limits (defaults shown)
# MAX_FILE_SIZE = "104857600"    # 100 MB
# STORAGE_QUOTA = "10737418240"  # 10 GB

[[r2_buckets]]
binding = "BUCKET"
bucket_name = "your-bucket-name"

[[kv_namespaces]]
binding = "RATE_LIMIT_KV"
id = "your-rate-limit-kv-id"  # From Step 1

[[kv_namespaces]]
binding = "QUOTA_KV"
id = "your-quota-kv-id"  # From Step 1
```

## Step 5: Update GitHub Actions Secrets (if using CI/CD)

Add these secrets to your GitHub repository (Settings > Secrets > Actions):

- `CLOUDFLARE_API_TOKEN`: Your Cloudflare API token
- `CLOUDFLARE_ACCOUNT_ID`: Your Cloudflare account ID
- `USERNAME`: Your username (e.g., "admin")
- `PASSWORD_HASH`: Generated password hash from Step 2
- `JWT_SECRET`: Generated JWT secret from Step 3
- `WORKER_URL`: Your Worker URL
- `BUCKET_NAME`: Your R2 bucket name
- `RATE_LIMIT_KV_ID`: KV namespace ID from Step 1
- `QUOTA_KV_ID`: KV namespace ID from Step 1

Update `.github/workflows/main.yml` to use these secrets.

## Step 6: Deploy

```bash
# Build and deploy
npm run deploy
```

## Testing Your Setup

### Test Basic Auth

```bash
curl -u admin:your-password https://your-worker.workers.dev/webdav/
```

### Test JWT Authentication

1. Get access token:
```bash
curl -X POST https://your-worker.workers.dev/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}'
```

2. Use the access token:
```bash
curl https://your-worker.workers.dev/webdav/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Test Rate Limiting

Try logging in with wrong password 6 times - you should be blocked on the 6th attempt:

```bash
for i in {1..6}; do
  curl -X POST https://your-worker.workers.dev/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong-password"}'
  echo "\nAttempt $i"
done
```

## Security Features Enabled

After completing this setup, you have:

✅ **PBKDF2 Password Hashing** - Passwords stored securely with 100,000 iterations
✅ **JWT Authentication** - Short-lived access tokens (15min) + refresh tokens (7 days)
✅ **Rate Limiting** - 5 failed login attempts per 15 minutes, 1-hour block
✅ **CORS Protection** - Only your Worker domain allowed
✅ **Path Traversal Prevention** - Validates all file paths
✅ **File Validation** - Extension whitelist, size limits, MIME type checking
✅ **Storage Quota** - Tracks usage, enforces limits (100MB/file, 10GB total)

## Troubleshooting

### "Missing environment variable"

Make sure all required variables are set in `wrangler.toml`:
- `PASSWORD_HASH`
- `JWT_SECRET`
- `WORKER_URL`
- `RATE_LIMIT_KV` (KV binding)
- `QUOTA_KV` (KV binding)

### "Invalid password hash"

Your `PASSWORD_HASH` must be in the format: `v1:iterations:base64(salt):base64(hash)`

Re-generate using Step 2.

### "401 Unauthorized"

1. Check your password hash is correct
2. Verify username matches `USERNAME` in `wrangler.toml`
3. Check CORS settings if accessing from browser

### Rate limit not working

Verify `RATE_LIMIT_KV` is properly bound in `wrangler.toml` and the namespace ID is correct.

## Next Steps

- **Stage 2**: TOTP Two-Factor Authentication (2FA)
- **Stage 3**: WebAuthn Passkeys (biometric authentication)

See `docs/plans/2025-12-10-security-enhancement-design.md` for the complete roadmap.

## Need Help?

Open an issue on GitHub or refer to the design document at:
`docs/plans/2025-12-10-security-enhancement-design.md`
