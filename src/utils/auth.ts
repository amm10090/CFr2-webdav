// 文件名：src/utils/auth.ts
import type { Env, AuthContext, TwoFactorData } from '../types';
import { verifyPassword } from './crypto';
import { verifyToken, extractToken, generateAccessToken, generateRefreshToken, generatePartialToken } from './jwt';
import {
	checkRateLimit,
	getRateLimitStatus,
	resetRateLimit,
	blockIdentifier,
	getClientIdentifier,
	LOGIN_RATE_LIMIT,
} from './rateLimit';
import { generateTOTPSecret, verifyTOTP, generateTOTPUri } from './totp';
import { generateRecoveryCodes, hashRecoveryCode, verifyRecoveryCode } from './recoveryCodes';

/**
 * Authenticate a request using hybrid authentication
 *
 * Supports two authentication methods:
 * 1. Basic Auth with password hash verification
 * 2. Bearer token (JWT) authentication
 *
 * @param request - Incoming request to authenticate
 * @param env - Environment bindings
 * @returns AuthContext if authenticated, null otherwise
 */
export async function authenticate(request: Request, env: Env): Promise<AuthContext | null> {
	const authHeader = request.headers.get('Authorization');
	if (!authHeader) {
		return null;
	}

	// Try JWT authentication first (Bearer token)
	if (authHeader.startsWith('Bearer ')) {
		return await authenticateJWT(authHeader, env);
	}

	// Fall back to Basic authentication
	if (authHeader.startsWith('Basic ')) {
		return await authenticateBasic(authHeader, env, request);
	}

	// Unknown authentication type
	return null;
}

/**
 * Authenticate using JWT (Bearer token)
 *
 * @param authHeader - Authorization header value
 * @param env - Environment bindings
 * @returns AuthContext if valid token, null otherwise
 */
async function authenticateJWT(authHeader: string, env: Env): Promise<AuthContext | null> {
	const token = extractToken(authHeader);
	if (!token) {
		return null;
	}

	// Verify JWT token
	const payload = await verifyToken(token, env.JWT_SECRET);
	if (!payload) {
		return null; // Invalid or expired token
	}

	// Only access tokens can be used for API requests
	if (payload.type !== 'access') {
		return null;
	}

	return {
		userId: payload.sub,
		tokenType: payload.type,
		authenticated: true,
	};
}

/**
 * Authenticate using Basic Auth with password hash verification
 *
 * @param authHeader - Authorization header value
 * @param env - Environment bindings
 * @param request - Request object for rate limiting
 * @returns AuthContext if valid credentials, null otherwise
 */
async function authenticateBasic(authHeader: string, env: Env, request: Request): Promise<AuthContext | null> {
	try {
		const authValue = authHeader.split(' ')[1];
		if (!authValue) {
			return null;
		}

		const [username, password] = atob(authValue).split(':');
		if (!username || !password) {
			return null;
		}

		// Check username
		if (username !== env.USERNAME) {
			return null;
		}

		// Rate limiting for login attempts（多粒度：IP / 用户名 / 组合，防止绕过）
		const rateLimitResult = await enforceLoginRateLimit(env, username, request);
		if (!rateLimitResult.allowed) {
			return null;
		}

		// Verify password（优先哈希，兼容旧版明文）
		const isValid = await verifyPasswordWithFallback(password, env);

		if (!isValid) {
			// Invalid password - don't reset rate limit
			return null;
		}

		// Successful authentication - reset rate limit
		await resetLoginRateLimits(env, username, request);

		return {
			userId: username,
			authenticated: true,
		};
	} catch {
		// Invalid base64 or other parsing error
		return null;
	}
}

/**
 * Handle login request to generate JWT tokens
 *
 * Expects JSON body with username and password.
 * Returns access and refresh tokens if credentials are valid.
 *
 * @param request - Login request with JSON body
 * @param env - Environment bindings
 * @returns Response with tokens or error
 */
export async function handleLogin(request: Request, env: Env): Promise<Response> {
	try {
		// Parse request body
		const body = await safeJson<{ username: string; password: string }>(request);
		const { username, password } = body;

		if (!username || !password) {
			return new Response(JSON.stringify({ error: 'Missing username or password' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Rate limiting（IP + 用户名 + 组合）
		const rateLimit = await enforceLoginRateLimit(env, username, request, true);
		if (!rateLimit.allowed) {
			const retryAfter = rateLimit.retryAfter ?? 3600;
			return new Response(JSON.stringify({ error: 'Too many login attempts' }), {
				status: 429,
				headers: {
					'Content-Type': 'application/json',
					'Retry-After': retryAfter.toString(),
				},
			});
		}

		// Verify username
		if (username !== env.USERNAME) {
			return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
				status: 401,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Verify password
		const isValid = await verifyPasswordWithFallback(password, env);
		if (!isValid) {
			return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
				status: 401,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Success - reset rate limit
		await resetLoginRateLimits(env, username, request);

		// Check if 2FA is enabled
		const twoFactorData = await get2FAData(env, username);
		if (twoFactorData?.totpEnabled) {
			// 2FA is enabled - return partial token
			const partialToken = await generatePartialToken(username, env.JWT_SECRET);

			return new Response(
				JSON.stringify({
					requires2FA: true,
					partialToken,
					message: 'Please provide your 2FA code to complete login',
				}),
				{
					status: 200,
					headers: { 'Content-Type': 'application/json' },
				}
			);
		}

		// 2FA not enabled - generate full tokens
		const accessToken = await generateAccessToken(username, env.JWT_SECRET);
		const refreshToken = await generateRefreshToken(username, env.JWT_SECRET);

		return new Response(
			JSON.stringify({
				accessToken,
				refreshToken,
				user: { username },
				expiresIn: 900, // 15 minutes in seconds
			}),
			{
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			}
		);
	} catch (error) {
		if (error instanceof Response) {
			return error; // safeJson 返回的 400
		}
		console.error('Login error:', error);
		return new Response(JSON.stringify({ error: 'Internal server error' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}

/**
 * Handle refresh token request to generate new access token
 *
 * Expects JSON body with refresh token.
 * Returns new access token if refresh token is valid.
 *
 * @param request - Refresh request with JSON body
 * @param env - Environment bindings
 * @returns Response with new access token or error
 */
export async function handleRefresh(request: Request, env: Env): Promise<Response> {
	try {
		// Parse request body
		const body = await safeJson<{ refreshToken: string }>(request);
		const { refreshToken } = body;

		if (!refreshToken) {
			return new Response(JSON.stringify({ error: 'Missing refresh token' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Verify refresh token
		const payload = await verifyToken(refreshToken, env.JWT_SECRET);
		if (!payload || payload.type !== 'refresh') {
			return new Response(JSON.stringify({ error: 'Invalid refresh token' }), {
				status: 401,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Generate new access token
		const accessToken = await generateAccessToken(payload.sub, env.JWT_SECRET);

		return new Response(
			JSON.stringify({
				accessToken,
				expiresIn: 900, // 15 minutes in seconds
			}),
			{
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			}
		);
	} catch (error) {
		if (error instanceof Response) {
			return error; // safeJson 返回的 400
		}
		console.error('Refresh error:', error);
		return new Response(JSON.stringify({ error: 'Internal server error' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}

/**
 * Create an unauthorized (401) response
 *
 * Includes WWW-Authenticate header for Basic auth clients.
 *
 * @param message - Optional error message
 * @returns 401 Response
 */
export function createUnauthorizedResponse(message = 'Unauthorized'): Response {
	return new Response(message, {
		status: 401,
		headers: {
			'WWW-Authenticate': 'Basic realm="CFr2-WebDAV"',
			'Content-Type': 'text/plain',
		},
	});
}

/**
 * 尝试解析 JSON，解析失败返回 400 而非 500
 */
async function safeJson<T>(request: Request): Promise<T> {
	try {
		return await request.json<T>();
	} catch {
		throw new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
			status: 400,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}

/**
 * Multi-tier login rate limiting with single-increment enforcement
 *
 * Enforces rate limits across three dimensions (IP-only, user-only, user+IP combination)
 * while only incrementing the counter once per request to avoid triple-counting.
 *
 * Implementation:
 * 1. First checks all three keys in read-only mode (getRateLimitStatus)
 * 2. If any key is already blocked, returns immediately without incrementing
 * 3. Only increments the most granular key (user+IP combo)
 * 4. If that increment triggers blocking, propagates block to other keys
 *
 * This prevents the issue where a single failed login would increment counters
 * three times (once per key), causing users to be blocked after ~2 attempts
 * instead of the configured 5 attempts.
 *
 * @param env - Environment variables
 * @param username - Username being authenticated
 * @param request - HTTP request for extracting client identifier
 * @param returnDetail - If true, return retry-after timing in response
 * @returns Object with allowed flag and optional retryAfter seconds
 */
async function enforceLoginRateLimit(
	env: Env,
	username: string,
	request: Request,
	returnDetail = false,
): Promise<{ allowed: boolean; retryAfter?: number }> {
	const clientId = getClientIdentifier(request);
	const keyIp = `login:ip:${clientId}`;
	const keyUser = `login:user:${username}`;
	const keyCombo = `login:user-ip:${username}:${clientId}`;

	// Phase 1: Check all keys in read-only mode (no increments)
	const [ipStatus, userStatus, comboStatus] = await Promise.all([
		getRateLimitStatus(env.RATE_LIMIT_KV, keyIp, LOGIN_RATE_LIMIT),
		getRateLimitStatus(env.RATE_LIMIT_KV, keyUser, LOGIN_RATE_LIMIT),
		getRateLimitStatus(env.RATE_LIMIT_KV, keyCombo, LOGIN_RATE_LIMIT),
	]);

	// If any key is already blocked, reject immediately without incrementing
	const blockedStatuses = [ipStatus, userStatus, comboStatus].filter((s) => !s.allowed);
	if (blockedStatuses.length > 0) {
		// Find the maximum blocked time across all blocked keys
		const blockedUntil = Math.max(
			...blockedStatuses
				.map((s) => s.blockedUntil ?? s.resetAt ?? 0)
				.filter((v) => v > 0)
		);

		if (returnDetail && blockedUntil > 0) {
			const retryAfter = Math.max(1, Math.ceil((blockedUntil - Date.now()) / 1000));
			return { allowed: false, retryAfter };
		}

		return { allowed: false };
	}

	// Phase 2: All keys are under threshold, increment only the most granular key (combo)
	const comboCheck = await checkRateLimit(env.RATE_LIMIT_KV, keyCombo, LOGIN_RATE_LIMIT);
	if (comboCheck.allowed) {
		return { allowed: true };
	}

	// Phase 3: Combo key reached threshold, propagate block to related keys
	// This ensures consistent enforcement across all dimensions
	const blockedUntil = comboCheck.blockedUntil ?? Date.now() + LOGIN_RATE_LIMIT.blockDurationMs;

	await Promise.all([
		blockIdentifier(env.RATE_LIMIT_KV, keyIp, LOGIN_RATE_LIMIT),
		blockIdentifier(env.RATE_LIMIT_KV, keyUser, LOGIN_RATE_LIMIT),
	]);

	if (returnDetail) {
		const retryAfter = Math.max(1, Math.ceil((blockedUntil - Date.now()) / 1000));
		return { allowed: false, retryAfter };
	}

	return { allowed: false };
}

/**
 * 登录成功后重置所有相关限流键
 */
async function resetLoginRateLimits(env: Env, username: string, request: Request): Promise<void> {
	const clientId = getClientIdentifier(request);
	const keys = [
		`login:ip:${clientId}`,
		`login:user:${username}`,
		`login:user-ip:${username}:${clientId}`,
	];

	await Promise.all(keys.map((key) => resetRateLimit(env.RATE_LIMIT_KV, key)));
}

/**
 * 验证密码，优先使用 PBKDF2 哈希，回退到旧版明文字段
 */
async function verifyPasswordWithFallback(password: string, env: Env): Promise<boolean> {
	if (env.PASSWORD_HASH) {
		try {
			return await verifyPassword(password, env.PASSWORD_HASH);
		} catch {
			// 如果哈希格式不合法，当作验证失败处理
			return false;
		}
	}

	if (env.PASSWORD) {
		return password === env.PASSWORD;
	}

	return false;
}

// ==================== Two-Factor Authentication Functions ====================

/**
 * Get TOTP KV key for a user
 */
function getTotpKey(username: string): string {
	return `user:totp:${username}`;
}

/**
 * Get 2FA data for a user from KV
 */
async function get2FAData(env: Env, username: string): Promise<TwoFactorData | null> {
	const key = getTotpKey(username);
	const data = await env.TOTP_KV.get(key);
	if (!data) {
		return null;
	}
	return JSON.parse(data) as TwoFactorData;
}

/**
 * Save 2FA data for a user to KV
 */
async function save2FAData(env: Env, username: string, data: TwoFactorData): Promise<void> {
	const key = getTotpKey(username);
	await env.TOTP_KV.put(key, JSON.stringify(data));
}

/**
 * Setup 2FA - Generate TOTP secret and recovery codes
 *
 * POST /auth/2fa/setup
 * Requires authentication
 *
 * @returns TOTP secret, QR code URI, and recovery codes
 */
export async function handle2FASetup(request: Request, env: Env, authContext: AuthContext): Promise<Response> {
	try {
		const username = authContext.userId;

		// Check if 2FA is already enabled
		const existing2FA = await get2FAData(env, username);
		if (existing2FA?.totpEnabled) {
			return new Response(JSON.stringify({ error: '2FA is already enabled. Disable it first to re-setup.' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Generate TOTP secret
		const totpSecret = await generateTOTPSecret();

		// Generate QR code URI
		const qrCodeUri = generateTOTPUri(totpSecret, username);

		// Generate recovery codes
		const recoveryCodes = generateRecoveryCodes(10);

		// Hash recovery codes for storage
		const hashedCodes = await Promise.all(recoveryCodes.map((code) => hashRecoveryCode(code)));

		// Store 2FA data (not enabled yet - needs verification)
		const data: TwoFactorData = {
			totpSecret,
			totpEnabled: false,
			recoveryCodes: hashedCodes,
		};
		await save2FAData(env, username, data);

		return new Response(
			JSON.stringify({
				secret: totpSecret,
				qrCodeUri,
				recoveryCodes,
				message: 'Please verify the setup by entering a code from your authenticator app.',
			}),
			{
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			}
		);
	} catch (error) {
		console.error('2FA setup error:', error);
		return new Response(JSON.stringify({ error: 'Internal server error' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}

/**
 * Verify and enable 2FA setup
 *
 * POST /auth/2fa/verify-setup
 * Body: { code: string }
 * Requires authentication
 */
export async function handle2FAVerifySetup(request: Request, env: Env, authContext: AuthContext): Promise<Response> {
	try {
		const username = authContext.userId;

		const body = await safeJson<{ code: string }>(request);
		const { code } = body;

		if (!code || code.length !== 6) {
			return new Response(JSON.stringify({ error: 'Invalid code format' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Get 2FA data
		const data = await get2FAData(env, username);
		if (!data) {
			return new Response(JSON.stringify({ error: '2FA setup not initiated. Please run /auth/2fa/setup first.' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		if (data.totpEnabled) {
			return new Response(JSON.stringify({ error: '2FA is already enabled' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Verify TOTP code
		const isValid = await verifyTOTP(data.totpSecret, code);
		if (!isValid) {
			return new Response(JSON.stringify({ error: 'Invalid verification code' }), {
				status: 401,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Enable 2FA
		data.totpEnabled = true;
		data.enabledAt = Date.now();
		await save2FAData(env, username, data);

		return new Response(
			JSON.stringify({
				success: true,
				message: '2FA has been successfully enabled',
			}),
			{
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			}
		);
	} catch (error) {
		if (error instanceof Response) {
			return error;
		}
		console.error('2FA verify setup error:', error);
		return new Response(JSON.stringify({ error: 'Internal server error' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}

/**
 * Disable 2FA
 *
 * POST /auth/2fa/disable
 * Body: { password: string }
 * Requires authentication
 */
export async function handle2FADisable(request: Request, env: Env, authContext: AuthContext): Promise<Response> {
	try {
		const username = authContext.userId;

		const body = await safeJson<{ password: string }>(request);
		const { password } = body;

		if (!password) {
			return new Response(JSON.stringify({ error: 'Password is required to disable 2FA' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Verify password
		const isValid = await verifyPasswordWithFallback(password, env);
		if (!isValid) {
			return new Response(JSON.stringify({ error: 'Invalid password' }), {
				status: 401,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Delete 2FA data
		const key = getTotpKey(username);
		await env.TOTP_KV.delete(key);

		return new Response(
			JSON.stringify({
				success: true,
				message: '2FA has been disabled',
			}),
			{
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			}
		);
	} catch (error) {
		if (error instanceof Response) {
			return error;
		}
		console.error('2FA disable error:', error);
		return new Response(JSON.stringify({ error: 'Internal server error' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}

/**
 * Get 2FA status
 *
 * GET /auth/2fa/status
 * Requires authentication
 */
export async function handle2FAStatus(request: Request, env: Env, authContext: AuthContext): Promise<Response> {
	try {
		const username = authContext.userId;

		const data = await get2FAData(env, username);

		return new Response(
			JSON.stringify({
				enabled: data?.totpEnabled ?? false,
				enabledAt: data?.enabledAt,
				lastUsedAt: data?.lastUsedAt,
			}),
			{
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			}
		);
	} catch (error) {
		console.error('2FA status error:', error);
		return new Response(JSON.stringify({ error: 'Internal server error' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}

/**
 * Verify 2FA code during login
 *
 * POST /auth/2fa/verify
 * Body: { partialToken: string, code: string, recoveryCode?: string }
 *
 * Completes the login process after password verification when 2FA is enabled
 */
export async function handle2FAVerify(request: Request, env: Env): Promise<Response> {
	try {
		const body = await safeJson<{ partialToken: string; code?: string; recoveryCode?: string }>(request);
		const { partialToken, code, recoveryCode } = body;

		if (!partialToken) {
			return new Response(JSON.stringify({ error: 'Partial token is required' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Verify partial token
		const payload = await verifyToken(partialToken, env.JWT_SECRET);
		if (!payload || payload.type !== 'partial') {
			return new Response(JSON.stringify({ error: 'Invalid or expired partial token' }), {
				status: 401,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		const username = payload.sub;

		// Get 2FA data
		const data = await get2FAData(env, username);
		if (!data || !data.totpEnabled) {
			return new Response(JSON.stringify({ error: '2FA is not enabled for this account' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		let verified = false;
		let usedRecoveryCode = false;

		// Try TOTP code first
		if (code) {
			verified = await verifyTOTP(data.totpSecret, code);
		}

		// Try recovery code if TOTP failed
		if (!verified && recoveryCode) {
			for (let i = 0; i < data.recoveryCodes.length; i++) {
				const isValid = await verifyRecoveryCode(recoveryCode, data.recoveryCodes[i]);
				if (isValid) {
					verified = true;
					usedRecoveryCode = true;
					// Remove used recovery code
					data.recoveryCodes.splice(i, 1);
					await save2FAData(env, username, data);
					break;
				}
			}
		}

		if (!verified) {
			return new Response(JSON.stringify({ error: 'Invalid 2FA code or recovery code' }), {
				status: 401,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Update last used timestamp
		data.lastUsedAt = Date.now();
		await save2FAData(env, username, data);

		// Generate full access tokens
		const accessToken = await generateAccessToken(username, env.JWT_SECRET);
		const refreshToken = await generateRefreshToken(username, env.JWT_SECRET);

		return new Response(
			JSON.stringify({
				success: true,
				accessToken,
				refreshToken,
				user: { username },
				usedRecoveryCode,
				remainingRecoveryCodes: data.recoveryCodes.length,
			}),
			{
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			}
		);
	} catch (error) {
		if (error instanceof Response) {
			return error;
		}
		console.error('2FA verify error:', error);
		return new Response(JSON.stringify({ error: 'Internal server error' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}
