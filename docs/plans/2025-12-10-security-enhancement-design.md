# CFr2-webdav 安全增强与现代认证系统设计方案

**日期**: 2025-12-10
**版本**: 1.0
**使用场景**: 个人使用（单用户或少数信任用户）

## 概述

本设计方案旨在解决当前 CFr2-webdav 项目中的安全漏洞，并引入现代认证机制，包括 JWT、TOTP 两步验证和 WebAuthn Passkeys。

## 需求收集结果

### 使用场景
- **类型**: 个人使用
- **用户数量**: 主要是单用户，可能扩展到少数信任用户
- **访问方式**:
  - WebDAV 客户端（Cyberduck, rclone 等）
  - Web 浏览器界面（仅从 Worker 自己的域名）

### CORS 需求
- 仅允许 Worker 自己的域名访问
- 不需要支持第三方域名跨域请求
- 严格的同源策略

### 认证需求
- 混合认证模式：
  - 基础用户名/密码登录
  - 登录后获得 JWT token
  - 后续请求使用 token 验证
- 两步验证支持（TOTP）
- WebAuthn Passkeys 支持（无密码登录）

### 文件上传限制
- 单文件最大：100 MB
- 总存储配额：10 GB（可配置）
- 文件名白名单验证
- Content-Type 验证

## 三阶段实施计划

### 阶段 1：安全基础修复（高优先级）

**目标**: 修复当前的严重安全漏洞，建立安全的认证基础

#### 1.1 CORS 配置修复
**文件**: `src/utils/cors.ts`

**问题**:
- 当前反射所有 Origin 头，完全绕过同源策略
- 任何域名都可以跨域访问 API

**解决方案**:
```typescript
// 配置允许的来源
const ALLOWED_ORIGINS = [
  process.env.WORKER_URL, // Worker 自己的 URL
  // 'https://custom-domain.com' // 如果需要自定义域名
];

export function setCORSHeaders(response: Response, request: Request): void {
  const origin = request.headers.get('Origin');

  // 只有在允许列表中的 origin 才设置 CORS 头
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    response.headers.set('Access-Control-Allow-Origin', origin);
    response.headers.set('Access-Control-Allow-Credentials', 'true');
  }

  // 其他 CORS 头保持不变
  response.headers.set('Access-Control-Allow-Methods', '...');
  response.headers.set('Access-Control-Allow-Headers', '...');
  response.headers.set('Access-Control-Max-Age', '86400');
}
```

#### 1.2 路径遍历保护
**文件**: `src/utils/webdavUtils.ts`

**问题**:
- 没有验证路径是否包含 `../` 等危险序列
- 可能访问 bucket 外的资源或敏感路径

**解决方案**:
```typescript
export function make_resource_path(request: Request): string {
  const url = new URL(request.url);
  const normalized = url.pathname.replace(/\/+/g, '/');
  let sliced = normalized.slice(1);

  // 去掉 webdav 前缀
  const withoutPrefix = sliced.startsWith('webdav/')
    ? sliced.slice('webdav/'.length)
    : sliced === 'webdav' ? '' : sliced;

  const decoded = decodeURIComponent(withoutPrefix);

  // 安全验证
  validatePath(decoded);

  return decoded;
}

function validatePath(path: string): void {
  // 禁止路径遍历
  if (path.includes('..')) {
    throw new Error('Path traversal not allowed');
  }

  // 禁止绝对路径
  if (path.startsWith('/')) {
    throw new Error('Absolute paths not allowed');
  }

  // 禁止危险字符
  const dangerousChars = /[\x00-\x1f\x7f<>:"|?*]/;
  if (dangerousChars.test(path)) {
    throw new Error('Invalid characters in path');
  }

  // 路径长度限制
  if (path.length > 1024) {
    throw new Error('Path too long');
  }
}
```

#### 1.3 密码哈希存储
**新文件**: `src/utils/crypto.ts`

**问题**:
- 当前使用明文密码比较
- 没有使用密码哈希

**解决方案**:
使用 Web Crypto API 实现 PBKDF2 密码哈希：
```typescript
export async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    'raw',
    data,
    { name: 'PBKDF2' },
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

  // 返回 salt + hash 的 base64 编码
  const hashArray = new Uint8Array(derivedBits);
  const combined = new Uint8Array(salt.length + hashArray.length);
  combined.set(salt);
  combined.set(hashArray, salt.length);

  return btoa(String.fromCharCode(...combined));
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  // 从 hash 中提取 salt 和哈希值
  const combined = Uint8Array.from(atob(hash), c => c.charCodeAt(0));
  const salt = combined.slice(0, 16);
  const storedHash = combined.slice(16);

  // 使用相同的 salt 计算新哈希
  const encoder = new TextEncoder();
  const data = encoder.encode(password);

  const key = await crypto.subtle.importKey(
    'raw',
    data,
    { name: 'PBKDF2' },
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

  const newHash = new Uint8Array(derivedBits);

  // 恒定时间比较
  return timingSafeEqual(newHash, storedHash);
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}
```

#### 1.4 JWT Token 认证
**新文件**: `src/utils/jwt.ts`

实现 JWT token 的生成、验证和刷新：
```typescript
interface JWTPayload {
  sub: string; // 用户 ID
  iat: number; // 签发时间
  exp: number; // 过期时间
  type: 'access' | 'refresh';
}

export async function generateAccessToken(userId: string, secret: string): Promise<string> {
  const payload: JWTPayload = {
    sub: userId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (15 * 60), // 15 分钟
    type: 'access'
  };

  return await createJWT(payload, secret);
}

export async function generateRefreshToken(userId: string, secret: string): Promise<string> {
  const payload: JWTPayload = {
    sub: userId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60), // 7 天
    type: 'refresh'
  };

  return await createJWT(payload, secret);
}

export async function verifyToken(token: string, secret: string): Promise<JWTPayload> {
  // JWT 验证实现
  // 使用 HMAC-SHA256 验证签名
  // 检查过期时间
}
```

#### 1.5 速率限制
**新文件**: `src/utils/rateLimit.ts`

使用 Workers KV 实现速率限制：
```typescript
interface RateLimitConfig {
  maxAttempts: number;
  windowMs: number;
  blockDurationMs: number;
}

const LOGIN_RATE_LIMIT: RateLimitConfig = {
  maxAttempts: 5,
  windowMs: 15 * 60 * 1000, // 15 分钟
  blockDurationMs: 60 * 60 * 1000 // 1 小时
};

export async function checkRateLimit(
  kv: KVNamespace,
  identifier: string, // IP 或用户名
  config: RateLimitConfig = LOGIN_RATE_LIMIT
): Promise<{ allowed: boolean; remainingAttempts: number }> {
  const key = `ratelimit:${identifier}`;
  const now = Date.now();

  // 从 KV 获取当前状态
  const data = await kv.get(key, 'json') as {
    attempts: number;
    windowStart: number;
    blockedUntil?: number;
  } | null;

  // 检查是否被封禁
  if (data?.blockedUntil && data.blockedUntil > now) {
    return { allowed: false, remainingAttempts: 0 };
  }

  // 检查窗口是否过期
  if (!data || (now - data.windowStart) > config.windowMs) {
    // 新窗口
    await kv.put(key, JSON.stringify({
      attempts: 1,
      windowStart: now
    }), { expirationTtl: Math.floor(config.windowMs / 1000) });

    return { allowed: true, remainingAttempts: config.maxAttempts - 1 };
  }

  // 检查是否超过限制
  if (data.attempts >= config.maxAttempts) {
    // 封禁用户
    await kv.put(key, JSON.stringify({
      ...data,
      blockedUntil: now + config.blockDurationMs
    }), { expirationTtl: Math.floor(config.blockDurationMs / 1000) });

    return { allowed: false, remainingAttempts: 0 };
  }

  // 增加尝试次数
  await kv.put(key, JSON.stringify({
    attempts: data.attempts + 1,
    windowStart: data.windowStart
  }), { expirationTtl: Math.floor(config.windowMs / 1000) });

  return {
    allowed: true,
    remainingAttempts: config.maxAttempts - data.attempts - 1
  };
}
```

#### 1.6 输入验证
**新文件**: `src/utils/validation.ts`

```typescript
const FILE_SIZE_LIMIT = 100 * 1024 * 1024; // 100 MB
const TOTAL_STORAGE_LIMIT = 10 * 1024 * 1024 * 1024; // 10 GB

// 允许的文件扩展名（白名单）
const ALLOWED_EXTENSIONS = new Set([
  // 文档
  'txt', 'md', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
  // 图片
  'jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'bmp', 'ico',
  // 音视频
  'mp3', 'mp4', 'wav', 'flac', 'mov', 'webm', 'avi',
  // 压缩包
  'zip', 'rar', '7z', 'tar', 'gz',
  // 代码
  'js', 'ts', 'jsx', 'tsx', 'css', 'html', 'json', 'xml', 'yml', 'yaml',
  'py', 'java', 'c', 'cpp', 'h', 'go', 'rs', 'sh',
]);

// 危险的 MIME types（黑名单）
const DANGEROUS_MIME_TYPES = new Set([
  'application/x-msdownload',
  'application/x-executable',
  'application/x-sharedlib',
  'application/x-sh',
  'text/x-shellscript',
]);

export function validateFileName(filename: string): void {
  if (!filename || filename.length === 0) {
    throw new Error('Filename cannot be empty');
  }

  if (filename.length > 255) {
    throw new Error('Filename too long');
  }

  // 检查危险字符
  const dangerousChars = /[\x00-\x1f\x7f<>:"|?*\\\/]/;
  if (dangerousChars.test(filename)) {
    throw new Error('Filename contains invalid characters');
  }

  // 检查扩展名
  const ext = filename.split('.').pop()?.toLowerCase();
  if (ext && !ALLOWED_EXTENSIONS.has(ext)) {
    throw new Error(`File extension '.${ext}' is not allowed`);
  }

  // 禁止隐藏文件（可选）
  if (filename.startsWith('.')) {
    throw new Error('Hidden files are not allowed');
  }
}

export function validateFileSize(size: number): void {
  if (size > FILE_SIZE_LIMIT) {
    throw new Error(`File size exceeds limit of ${FILE_SIZE_LIMIT / 1024 / 1024} MB`);
  }
}

export function validateContentType(contentType: string | null): void {
  if (!contentType) {
    return; // 允许未指定
  }

  if (DANGEROUS_MIME_TYPES.has(contentType)) {
    throw new Error('Content-Type not allowed for security reasons');
  }
}

export async function checkStorageQuota(
  bucket: R2Bucket,
  newFileSize: number
): Promise<void> {
  // 注意：R2 没有直接的 API 获取总大小，需要自己维护
  // 可以使用 KV 存储当前使用量
  // 这里提供接口，实际实现需要配合 KV

  // const currentUsage = await kv.get('storage:usage');
  // if (currentUsage + newFileSize > TOTAL_STORAGE_LIMIT) {
  //   throw new Error('Storage quota exceeded');
  // }
}
```

#### 1.7 认证流程改进
**修改文件**: `src/utils/auth.ts`, `src/handlers/requestHandler.ts`

新的认证流程：
1. 用户使用用户名/密码登录 → 验证密码哈希
2. 检查速率限制
3. 验证成功 → 生成 JWT access token 和 refresh token
4. 后续请求携带 JWT token 在 Authorization 头
5. WebDAV 客户端可以使用 Basic Auth（自动转换为 token）

### 阶段 2：TOTP 两步验证

**目标**: 添加基于时间的一次性密码（TOTP）两步验证

#### 2.1 TOTP 实现
**新文件**: `src/utils/totp.ts`

```typescript
// 使用 RFC 6238 TOTP 算法
export async function generateTOTPSecret(): Promise<string> {
  // 生成 20 字节随机密钥
  const secret = crypto.getRandomValues(new Uint8Array(20));
  return base32Encode(secret);
}

export async function verifyTOTP(secret: string, code: string): Promise<boolean> {
  // 验证当前时间窗口和前后一个窗口（30秒）
  const currentWindow = Math.floor(Date.now() / 1000 / 30);

  for (let window of [currentWindow - 1, currentWindow, currentWindow + 1]) {
    const expectedCode = await generateTOTPCode(secret, window);
    if (code === expectedCode) {
      return true;
    }
  }

  return false;
}

export function generateTOTPUri(
  secret: string,
  accountName: string,
  issuer: string = 'CFr2-WebDAV'
): string {
  return `otpauth://totp/${issuer}:${accountName}?secret=${secret}&issuer=${issuer}`;
}
```

#### 2.2 恢复码
**新文件**: `src/utils/recoveryCodes.ts`

```typescript
export function generateRecoveryCodes(count: number = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const code = Array.from(crypto.getRandomValues(new Uint8Array(4)))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();
    codes.push(code);
  }
  return codes;
}

export async function hashRecoveryCode(code: string): Promise<string> {
  // 使用 SHA-256 哈希恢复码
  const encoder = new TextEncoder();
  const data = encoder.encode(code);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}
```

#### 2.3 登录流程更新
1. 用户输入用户名/密码
2. 验证密码成功
3. 如果启用 2FA → 要求输入 TOTP 码
4. 验证 TOTP 码
5. 颁发 JWT token

### 阶段 3：WebAuthn Passkeys

**目标**: 支持 WebAuthn 标准的 Passkeys（指纹、Face ID、硬件密钥）

#### 3.1 WebAuthn 实现
**新文件**: `src/utils/webauthn.ts`

```typescript
// WebAuthn 注册流程
export async function generateRegistrationOptions(
  userId: string,
  username: string
): Promise<PublicKeyCredentialCreationOptions> {
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  return {
    challenge: challenge,
    rp: {
      name: 'CFr2 WebDAV',
      id: new URL(env.WORKER_URL).hostname
    },
    user: {
      id: new TextEncoder().encode(userId),
      name: username,
      displayName: username
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },  // ES256
      { type: 'public-key', alg: -257 } // RS256
    ],
    timeout: 60000,
    attestation: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      requireResidentKey: false,
      userVerification: 'preferred'
    }
  };
}

// WebAuthn 验证流程
export async function generateAuthenticationOptions(
  userId: string
): Promise<PublicKeyCredentialRequestOptions> {
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  // 从 KV 获取用户已注册的凭证
  const credentials = await getRegisteredCredentials(userId);

  return {
    challenge: challenge,
    timeout: 60000,
    rpId: new URL(env.WORKER_URL).hostname,
    allowCredentials: credentials.map(cred => ({
      type: 'public-key',
      id: cred.credentialId
    })),
    userVerification: 'preferred'
  };
}

// 验证 WebAuthn 响应
export async function verifyAuthenticationResponse(
  credential: PublicKeyCredential,
  challenge: Uint8Array,
  storedCredential: StoredCredential
): Promise<boolean> {
  // 实现 WebAuthn 验证逻辑
  // 验证签名、challenge、origin 等
}
```

#### 3.2 Passkey 管理界面
在 Web UI 中添加：
- 注册新 Passkey
- 查看已注册的 Passkeys
- 删除 Passkey
- 为每个 Passkey 设置友好名称

### 数据存储架构

**Workers KV 命名空间**: `AUTH_KV`

数据结构：
```typescript
// 用户凭证
Key: `user:${username}`
Value: {
  passwordHash: string,
  totpSecret?: string,
  totpEnabled: boolean,
  recoveryCodes?: string[], // 哈希后的恢复码
  createdAt: number,
  lastLogin: number
}

// JWT 刷新 token
Key: `refresh:${tokenId}`
Value: {
  userId: string,
  issuedAt: number,
  expiresAt: number
}

// Passkeys
Key: `passkey:${userId}:${credentialId}`
Value: {
  credentialId: string,
  publicKey: string,
  counter: number,
  name: string,
  createdAt: number
}

// 速率限制
Key: `ratelimit:${identifier}`
Value: {
  attempts: number,
  windowStart: number,
  blockedUntil?: number
}

// WebAuthn challenges（临时）
Key: `challenge:${challengeId}`
Value: {
  challenge: string,
  userId: string,
  expiresAt: number
}
TTL: 5 minutes

// 存储使用量跟踪
Key: `storage:usage`
Value: {
  totalBytes: number,
  lastUpdated: number
}
```

### 环境变量配置

新增环境变量：
```toml
# wrangler.toml
[vars]
USERNAME = "admin"
PASSWORD_HASH = "生成的密码哈希"
JWT_SECRET = "随机生成的密钥"
WORKER_URL = "https://your-worker.workers.dev"
MAX_FILE_SIZE = "104857600"  # 100 MB
STORAGE_QUOTA = "10737418240" # 10 GB

[[kv_namespaces]]
binding = "AUTH_KV"
id = "你的 KV 命名空间 ID"

[[r2_buckets]]
binding = "BUCKET"
bucket_name = "你的存储桶名称"
```

### API 端点设计

#### 认证相关端点
```
POST /api/auth/login
  Body: { username, password, totpCode? }
  Response: { accessToken, refreshToken, user }

POST /api/auth/refresh
  Body: { refreshToken }
  Response: { accessToken }

POST /api/auth/logout
  Body: { refreshToken }
  Response: { success }

GET /api/auth/me
  Headers: Authorization: Bearer <token>
  Response: { user, totpEnabled, passkeysCount }
```

#### 2FA 相关端点
```
POST /api/auth/totp/enable
  Response: { secret, qrCodeUri, recoveryCodes }

POST /api/auth/totp/verify
  Body: { code }
  Response: { success }

POST /api/auth/totp/disable
  Body: { password, code }
  Response: { success }

POST /api/auth/recovery/regenerate
  Body: { password }
  Response: { recoveryCodes }
```

#### Passkeys 相关端点
```
POST /api/auth/passkey/register/start
  Response: { options, challenge }

POST /api/auth/passkey/register/finish
  Body: { credential, challengeId, name }
  Response: { success, credentialId }

POST /api/auth/passkey/authenticate/start
  Body: { username }
  Response: { options, challenge }

POST /api/auth/passkey/authenticate/finish
  Body: { credential, challengeId }
  Response: { accessToken, refreshToken }

GET /api/auth/passkeys
  Response: [{ id, name, createdAt }]

DELETE /api/auth/passkey/:id
  Response: { success }
```

### 错误处理改进

统一错误响应格式：
```typescript
// WebDAV 操作错误（XML）
<?xml version="1.0" encoding="utf-8"?>
<D:error xmlns:D="DAV:">
  <D:error-code>403</D:error-code>
  <D:error-message>Forbidden</D:error-message>
</D:error>

// API 错误（JSON）
{
  "error": {
    "code": "AUTH_FAILED",
    "message": "Invalid credentials",
    "details": {}
  }
}
```

### 安全最佳实践

1. **密钥管理**：
   - 使用 Workers Secrets 存储敏感配置
   - 定期轮换 JWT secret

2. **会话管理**：
   - Access token 短期有效（15分钟）
   - Refresh token 长期有效（7天）但可撤销
   - 支持强制登出所有设备

3. **审计日志**：
   - 记录所有登录尝试
   - 记录认证方式变更
   - 记录敏感操作

4. **降级策略**：
   - 如果 KV 不可用，允许紧急访问模式
   - 保留环境变量作为后备认证方式

### 测试计划

每个阶段需要的测试：

#### 阶段 1 测试
- [ ] CORS 策略正确拒绝非法来源
- [ ] 路径遍历攻击被阻止
- [ ] 密码哈希验证正确
- [ ] JWT token 生成和验证
- [ ] 速率限制生效
- [ ] 文件上传验证（大小、类型、名称）

#### 阶段 2 测试
- [ ] TOTP 生成和验证
- [ ] QR 码正确显示
- [ ] 恢复码可以使用
- [ ] 2FA 可以启用/禁用

#### 阶段 3 测试
- [ ] Passkey 注册流程
- [ ] Passkey 登录流程
- [ ] 多个 Passkeys 管理
- [ ] 跨设备同步（取决于浏览器）

### 部署策略

1. **阶段 1 部署**：
   - 创建新的 KV 命名空间
   - 生成初始密码哈希
   - 部署代码
   - 验证基本功能
   - Git commit + 记忆系统存储

2. **阶段 2 部署**：
   - 在现有部署上增量更新
   - 测试 2FA 功能
   - Git commit + 记忆系统存储

3. **阶段 3 部署**：
   - 增量添加 Passkeys 支持
   - 测试跨浏览器兼容性
   - Git commit + 记忆系统存储

### 回滚计划

每个阶段都应该支持回滚：
- 保留环境变量配置作为后备
- 可以禁用新功能回退到基础认证
- KV 数据向后兼容

### 性能考虑

1. **KV 访问优化**：
   - 使用 KV 缓存 TTL
   - 批量读取减少请求

2. **JWT 验证**：
   - 缓存公钥减少计算
   - 使用对称加密（HMAC）而非非对称

3. **密码哈希**：
   - PBKDF2 迭代次数平衡安全和性能
   - 考虑使用 Workers 的 CPU 限制

## 总结

本设计方案采用分阶段实施策略，每个阶段都是独立可用的，可以根据需求和时间灵活调整。阶段 1 解决了所有严重的安全问题，是必须实施的。阶段 2 和 3 提供了额外的安全层，适合对安全有更高要求的场景。

通过使用现代 Web 标准（JWT、TOTP、WebAuthn）和 Cloudflare Workers 的强大功能，这个设计将 CFr2-webdav 从一个概念验证项目提升为生产就绪的安全解决方案。
