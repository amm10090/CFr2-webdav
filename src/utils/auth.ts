// 文件名：src/utils/auth.ts
import type {
	Env,
	AuthContext,
	TwoFactorData,
	PasskeyCredential,
	PasskeyRegisterFinishRequest,
	PasskeyAuthStartRequest,
	PasskeyAuthFinishRequest,
	PasskeyListItem,
} from '../types';
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
import { generateTOTPSecret, verifyTOTP, generateTOTPUri, TOTP_DIGITS } from './totp';
import { generateRecoveryCodes, hashRecoveryCode, verifyRecoveryCode } from './recoveryCodes';
import {
	generateChallenge,
	saveChallenge,
	getChallenge,
	deleteChallenge,
	generateRegistrationOptions,
	verifyRegistrationResponse,
	generateAuthenticationOptions,
	verifyAuthenticationResponse,
	base64urlEncode,
	base64urlDecode,
} from './webauthn';

// 2FA 验证尝试限流（5 次 / 10 分钟，封禁 1 小时）
const TWO_FA_VERIFY_RATE_LIMIT = {
	maxAttempts: 5,
	windowMs: 10 * 60 * 1000,
	blockDurationMs: 60 * 60 * 1000,
};

// Passkey 认证限流（10 次 / 15 分钟，封禁 1 小时）
const PASSKEY_AUTH_RATE_LIMIT = {
	maxAttempts: 10,
	windowMs: 15 * 60 * 1000,
	blockDurationMs: 60 * 60 * 1000,
};

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
				},
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
			},
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
			},
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
 * Create an unauthorized (401) response without WWW-Authenticate header.
 *
 * This prevents browsers from showing native Basic Auth popups.
 * Clients should handle authentication through the custom login page.
 *
 * @param message - Optional error message
 * @returns 401 Response
 */
export function createUnauthorizedResponse(message = 'Unauthorized'): Response {
	return new Response(message, {
		status: 401,
		headers: {
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
		const blockedUntil = Math.max(...blockedStatuses.map((s) => s.blockedUntil ?? s.resetAt ?? 0).filter((v) => v > 0));

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
	const keys = [`login:ip:${clientId}`, `login:user:${username}`, `login:user-ip:${username}:${clientId}`];

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
			},
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

		// Rate limiting for 2FA setup verification (user + IP combination)
		// Protects against brute-force attacks on TOTP codes during setup
		const clientId = getClientIdentifier(request);
		const rateLimitKey = `2fa-setup-verify:${username}:${clientId}`;
		const verifyRate = await checkRateLimit(env.RATE_LIMIT_KV, rateLimitKey, TWO_FA_VERIFY_RATE_LIMIT);
		if (!verifyRate.allowed) {
			const retryAfter =
				verifyRate.blockedUntil != null
					? Math.max(1, Math.ceil((verifyRate.blockedUntil - Date.now()) / 1000))
					: Math.max(1, Math.ceil(TWO_FA_VERIFY_RATE_LIMIT.blockDurationMs / 1000));

			return new Response(JSON.stringify({ error: 'Too many verification attempts' }), {
				status: 429,
				headers: {
					'Content-Type': 'application/json',
					'Retry-After': retryAfter.toString(),
				},
			});
		}

		const body = await safeJson<{ code: string }>(request);
		const { code } = body;

		if (!code || code.length !== TOTP_DIGITS || !/^\d+$/.test(code)) {
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

		// Reset rate limit on successful verification
		await resetRateLimit(env.RATE_LIMIT_KV, rateLimitKey);

		return new Response(
			JSON.stringify({
				success: true,
				message: '2FA has been successfully enabled',
			}),
			{
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			},
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
			},
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
 * Regenerate recovery codes
 *
 * POST /auth/2fa/recovery-codes/regenerate
 * Body: { password: string }
 * Requires authentication
 *
 * Generates new recovery codes and invalidates all existing ones.
 * Requires password confirmation for security.
 */
export async function handle2FARegenerateRecoveryCodes(
	request: Request,
	env: Env,
	authContext: AuthContext,
): Promise<Response> {
	try {
		const username = authContext.userId;

		// Multi-tier rate limiting before password verification (IP / User / Combo)
		// Prevents unlimited PBKDF2 hash attacks from distributed sources
		const clientId = getClientIdentifier(request);
		const keyIp = `2fa-recovery-regenerate:ip:${clientId}`;
		const keyUser = `2fa-recovery-regenerate:user:${username}`;
		const keyCombo = `2fa-recovery-regenerate:user-ip:${username}:${clientId}`;

		// Phase 1: Read-only check all keys
		const [ipStatus, userStatus, comboStatus] = await Promise.all([
			getRateLimitStatus(env.RATE_LIMIT_KV, keyIp, LOGIN_RATE_LIMIT),
			getRateLimitStatus(env.RATE_LIMIT_KV, keyUser, LOGIN_RATE_LIMIT),
			getRateLimitStatus(env.RATE_LIMIT_KV, keyCombo, LOGIN_RATE_LIMIT),
		]);

		// If any key is already blocked, reject immediately
		if (![ipStatus, userStatus, comboStatus].every((s) => s.allowed)) {
			const blockedUntil = Math.max(
				...[ipStatus, userStatus, comboStatus]
					.filter((s) => !s.allowed)
					.map((s) => s.blockedUntil ?? s.resetAt ?? 0)
					.filter((v) => v > 0),
			);
			const retryAfter = blockedUntil > 0 ? Math.max(1, Math.ceil((blockedUntil - Date.now()) / 1000)) : 3600;

			return new Response(JSON.stringify({ error: 'Too many attempts' }), {
				status: 429,
				headers: {
					'Content-Type': 'application/json',
					'Retry-After': retryAfter.toString(),
				},
			});
		}

		// Phase 2: Increment only combo key
		const comboCheck = await checkRateLimit(env.RATE_LIMIT_KV, keyCombo, LOGIN_RATE_LIMIT);
		if (!comboCheck.allowed) {
			// Phase 3: Propagate block to related keys
			await Promise.all([
				blockIdentifier(env.RATE_LIMIT_KV, keyIp, LOGIN_RATE_LIMIT),
				blockIdentifier(env.RATE_LIMIT_KV, keyUser, LOGIN_RATE_LIMIT),
			]);

			const retryAfter =
				comboCheck.blockedUntil != null
					? Math.max(1, Math.ceil((comboCheck.blockedUntil - Date.now()) / 1000))
					: Math.max(1, Math.ceil(LOGIN_RATE_LIMIT.blockDurationMs / 1000));

			return new Response(JSON.stringify({ error: 'Too many attempts' }), {
				status: 429,
				headers: {
					'Content-Type': 'application/json',
					'Retry-After': retryAfter.toString(),
				},
			});
		}

		const body = await safeJson<{ password: string }>(request);
		const { password } = body;

		if (!password) {
			return new Response(JSON.stringify({ error: 'Password is required to regenerate recovery codes' }), {
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

		// Check if 2FA is enabled
		const data = await get2FAData(env, username);
		if (!data || !data.totpEnabled) {
			return new Response(JSON.stringify({ error: '2FA is not enabled' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Generate new recovery codes
		const recoveryCodes = generateRecoveryCodes(10);

		// Hash recovery codes for storage
		const hashedCodes = await Promise.all(recoveryCodes.map((code) => hashRecoveryCode(code)));

		// Update 2FA data with new recovery codes (invalidates old ones)
		data.recoveryCodes = hashedCodes;
		await save2FAData(env, username, data);

		// Reset all rate limit keys on successful regeneration
		await Promise.all([
			resetRateLimit(env.RATE_LIMIT_KV, keyIp),
			resetRateLimit(env.RATE_LIMIT_KV, keyUser),
			resetRateLimit(env.RATE_LIMIT_KV, keyCombo),
		]);

		return new Response(
			JSON.stringify({
				success: true,
				recoveryCodes,
				message: 'Recovery codes have been regenerated. Please store them securely. Old codes are now invalid.',
			}),
			{
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			},
		);
	} catch (error) {
		if (error instanceof Response) {
			return error;
		}
		console.error('2FA regenerate recovery codes error:', error);
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
			},
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

		// 2FA 验证限流（按用户+IP 组合）
		const clientId = getClientIdentifier(request);
		const rateLimitKey = `2fa-verify:${username}:${clientId}`;
		const verifyRate = await checkRateLimit(env.RATE_LIMIT_KV, rateLimitKey, TWO_FA_VERIFY_RATE_LIMIT);
		if (!verifyRate.allowed) {
			const retryAfter =
				verifyRate.blockedUntil != null
					? Math.max(1, Math.ceil((verifyRate.blockedUntil - Date.now()) / 1000))
					: Math.max(1, Math.ceil(TWO_FA_VERIFY_RATE_LIMIT.blockDurationMs / 1000));

			return new Response(JSON.stringify({ error: 'Too many 2FA attempts' }), {
				status: 429,
				headers: {
					'Content-Type': 'application/json',
					'Retry-After': retryAfter.toString(),
				},
			});
		}

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

		// 成功后重置限流计数
		await resetRateLimit(env.RATE_LIMIT_KV, rateLimitKey);

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
			},
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

// ==================== WebAuthn Passkey Functions ====================

/**
 * Get AUTH_KV namespace (falls back to TOTP_KV if not configured)
 */
function getAuthKV(env: Env): KVNamespace {
	return env.AUTH_KV ?? env.TOTP_KV;
}

/**
 * Start passkey registration
 *
 * POST /auth/passkey/register/start
 * Requires authentication
 *
 * @returns PublicKeyCredentialCreationOptions and challenge ID
 */
export async function handlePasskeyRegisterStart(
	request: Request,
	env: Env,
	authContext: AuthContext,
): Promise<Response> {
	try {
		const username = authContext.userId;
		const kv = getAuthKV(env);

		// Generate challenge
		const challenge = generateChallenge();
		const challengeId = crypto.randomUUID();

		// Extract RP ID from request origin (supports both dev and prod)
		const origin = request.headers.get('Origin') || env.WORKER_URL;
		const rpId = new URL(origin).hostname;

		// Generate registration options
		const options = generateRegistrationOptions(username, username, rpId);

		// Save challenge to KV (5 minute TTL)
		await saveChallenge(kv, challengeId, challenge, username, 300);

		// Replace challenge in options with the saved one (for serialization)
		const serializableOptions = {
			...options,
			challenge: base64urlEncode(challenge),
			user: {
				...options.user,
				id: base64urlEncode(new Uint8Array(options.user.id as ArrayBuffer)),
			},
		};

		return new Response(
			JSON.stringify({
				options: serializableOptions,
				challengeId,
			}),
			{
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			},
		);
	} catch (error) {
		console.error('Passkey register start error:', error);
		return new Response(JSON.stringify({ error: 'Internal server error' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}

/**
 * Finish passkey registration
 *
 * POST /auth/passkey/register/finish
 * Body: { credential, challengeId, name? }
 * Requires authentication
 */
export async function handlePasskeyRegisterFinish(
	request: Request,
	env: Env,
	authContext: AuthContext,
): Promise<Response> {
	try {
		const username = authContext.userId;
		const kv = getAuthKV(env);

		const body = await safeJson<PasskeyRegisterFinishRequest>(request);
		const { credential, challengeId, name } = body;

		if (!credential || !challengeId) {
			return new Response(JSON.stringify({ error: 'Missing credential or challengeId' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Retrieve challenge
		const challengeRecord = await getChallenge(kv, challengeId);
		if (!challengeRecord) {
			return new Response(JSON.stringify({ error: 'Challenge not found or expired' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Verify user matches
		if (challengeRecord.userId !== username) {
			return new Response(JSON.stringify({ error: 'Challenge user mismatch' }), {
				status: 403,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Verify registration response
		const origin = request.headers.get('Origin') || env.WORKER_URL;
		const rpId = new URL(origin).hostname;
		const expectedChallenge = base64urlDecode(challengeRecord.challenge);

		// Normalize credential from client JSON format
		const normalizedCredential = normalizeWebAuthnCredential(credential);

		const verificationResult = await verifyRegistrationResponse(normalizedCredential, expectedChallenge, rpId, origin);

		// Delete challenge to prevent reuse
		await deleteChallenge(kv, challengeId);

		// Store passkey credential
		const passkeyData: PasskeyCredential = {
			credentialId: verificationResult.credentialId,
			publicKey: verificationResult.publicKey,
			counter: verificationResult.counter,
			name: name || `Passkey ${new Date().toLocaleDateString()}`,
			createdAt: Date.now(),
		};

		const key = `passkey:${username}:${verificationResult.credentialId}`;
		await kv.put(key, JSON.stringify(passkeyData));

		return new Response(
			JSON.stringify({
				success: true,
				credentialId: verificationResult.credentialId,
				message: 'Passkey registered successfully',
			}),
			{
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			},
		);
	} catch (error) {
		if (error instanceof Response) {
			return error;
		}
		console.error('Passkey register finish error:', error);
		return new Response(
			JSON.stringify({
				error: 'Registration verification failed',
				details: error instanceof Error ? error.message : 'Unknown error',
			}),
			{
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			},
		);
	}
}

/**
 * Start passkey authentication
 *
 * POST /auth/passkey/authenticate/start
 * Body: { username }
 * No authentication required
 */
export async function handlePasskeyAuthStart(request: Request, env: Env): Promise<Response> {
	try {
		const body = await safeJson<PasskeyAuthStartRequest>(request);
		const { username } = body;

		// Multi-tier rate limiting (IP / User / Combo) to prevent abuse
		const clientId = getClientIdentifier(request);
		const keyIp = `passkey-auth:ip:${clientId}`;
		const keyUser = username ? `passkey-auth:user:${username}` : '';
		const keyCombo = username ? `passkey-auth:user-ip:${username}:${clientId}` : '';

		// Phase 1: Read-only check all keys
		const statusChecks = [getRateLimitStatus(env.RATE_LIMIT_KV, keyIp, PASSKEY_AUTH_RATE_LIMIT)];
		if (keyUser) statusChecks.push(getRateLimitStatus(env.RATE_LIMIT_KV, keyUser, PASSKEY_AUTH_RATE_LIMIT));
		if (keyCombo) statusChecks.push(getRateLimitStatus(env.RATE_LIMIT_KV, keyCombo, PASSKEY_AUTH_RATE_LIMIT));

		const [ipStatus, userStatus, comboStatus] = await Promise.all(statusChecks).then(results => [
			results[0],
			results[1] || { allowed: true },
			results[2] || { allowed: true }
		]);

		// If any key is already blocked, reject immediately
		if (![ipStatus, userStatus, comboStatus].every((s) => s.allowed)) {
			const blockedUntil = Math.max(
				...[ipStatus, userStatus, comboStatus]
					.filter((s) => !s.allowed)
					.map((s) => s.blockedUntil ?? s.resetAt ?? 0)
					.filter((v) => v > 0),
			);
			const retryAfter = blockedUntil > 0 ? Math.max(1, Math.ceil((blockedUntil - Date.now()) / 1000)) : 3600;

			return new Response(JSON.stringify({ error: 'Too many authentication attempts' }), {
				status: 429,
				headers: {
					'Content-Type': 'application/json',
					'Retry-After': retryAfter.toString(),
				},
			});
		}

		// Phase 2: Increment only combo key if username provided
		if (keyCombo) {
			const comboCheck = await checkRateLimit(env.RATE_LIMIT_KV, keyCombo, PASSKEY_AUTH_RATE_LIMIT);
			if (!comboCheck.allowed) {
				// Phase 3: Propagate block to related keys
				const blockPromises = [blockIdentifier(env.RATE_LIMIT_KV, keyIp, PASSKEY_AUTH_RATE_LIMIT)];
				if (keyUser) blockPromises.push(blockIdentifier(env.RATE_LIMIT_KV, keyUser, PASSKEY_AUTH_RATE_LIMIT));
				await Promise.all(blockPromises);

				const retryAfter =
					comboCheck.blockedUntil != null
						? Math.max(1, Math.ceil((comboCheck.blockedUntil - Date.now()) / 1000))
						: Math.max(1, Math.ceil(PASSKEY_AUTH_RATE_LIMIT.blockDurationMs / 1000));

				return new Response(JSON.stringify({ error: 'Too many authentication attempts' }), {
					status: 429,
					headers: {
						'Content-Type': 'application/json',
						'Retry-After': retryAfter.toString(),
					},
				});
			}
		}

		const kv = getAuthKV(env);

		// Get user's passkeys
		const passkeys = username ? await listUserPasskeys(kv, username) : [];

		// SECURITY: To prevent account enumeration, always return 200 with options
		// If user has no passkeys, return empty allowCredentials
		// This makes it indistinguishable whether the user exists or has passkeys
		const challenge = generateChallenge();
		const challengeId = crypto.randomUUID();

		// Extract RP ID from request origin (supports both dev and prod)
		const origin = request.headers.get('Origin') || env.WORKER_URL;
		const rpId = new URL(origin).hostname;

		// Generate authentication options (empty allowCredentials if no passkeys)
		const options = generateAuthenticationOptions(username, passkeys, rpId);

		// Save challenge
		await saveChallenge(kv, challengeId, challenge, username || '', 300);

		// Serialize options
		const serializableOptions = {
			...options,
			challenge: base64urlEncode(challenge),
			allowCredentials: options.allowCredentials?.map((cred: { type: string; id: ArrayBuffer | Uint8Array }) => ({
				...cred,
				id: base64urlEncode(new Uint8Array(cred.id as ArrayBuffer)),
			})),
		};

		return new Response(
			JSON.stringify({
				options: serializableOptions,
				challengeId,
			}),
			{
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			},
		);
	} catch (error) {
		if (error instanceof Response) {
			return error;
		}
		console.error('Passkey auth start error:', error);
		return new Response(JSON.stringify({ error: 'Internal server error' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}

/**
 * Finish passkey authentication
 *
 * POST /auth/passkey/authenticate/finish
 * Body: { credential, challengeId }
 * No authentication required
 *
 * @returns JWT access and refresh tokens
 */
export async function handlePasskeyAuthFinish(request: Request, env: Env): Promise<Response> {
	try {
		const body = await safeJson<PasskeyAuthFinishRequest>(request);
		const { credential, challengeId } = body;

		if (!credential || !challengeId) {
			return new Response(JSON.stringify({ error: 'Missing credential or challengeId' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		const kv = getAuthKV(env);

		// Retrieve challenge
		const challengeRecord = await getChallenge(kv, challengeId);
		if (!challengeRecord) {
			return new Response(JSON.stringify({ error: 'Challenge not found or expired' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		const username = challengeRecord.userId;

		// Multi-tier rate limiting (IP / User / Combo) to prevent brute force
		const clientId = getClientIdentifier(request);
		const keyIp = `passkey-auth-finish:ip:${clientId}`;
		const keyUser = `passkey-auth-finish:user:${username}`;
		const keyCombo = `passkey-auth-finish:user-ip:${username}:${clientId}`;

		// Phase 1: Read-only check all keys
		const [ipStatus, userStatus, comboStatus] = await Promise.all([
			getRateLimitStatus(env.RATE_LIMIT_KV, keyIp, PASSKEY_AUTH_RATE_LIMIT),
			getRateLimitStatus(env.RATE_LIMIT_KV, keyUser, PASSKEY_AUTH_RATE_LIMIT),
			getRateLimitStatus(env.RATE_LIMIT_KV, keyCombo, PASSKEY_AUTH_RATE_LIMIT),
		]);

		// If any key is already blocked, reject immediately
		if (![ipStatus, userStatus, comboStatus].every((s) => s.allowed)) {
			const blockedUntil = Math.max(
				...[ipStatus, userStatus, comboStatus]
					.filter((s) => !s.allowed)
					.map((s) => s.blockedUntil ?? s.resetAt ?? 0)
					.filter((v) => v > 0),
			);
			const retryAfter = blockedUntil > 0 ? Math.max(1, Math.ceil((blockedUntil - Date.now()) / 1000)) : 3600;

			return new Response(JSON.stringify({ error: 'Too many authentication attempts' }), {
				status: 429,
				headers: {
					'Content-Type': 'application/json',
					'Retry-After': retryAfter.toString(),
				},
			});
		}

		// Phase 2: Increment only combo key
		const comboCheck = await checkRateLimit(env.RATE_LIMIT_KV, keyCombo, PASSKEY_AUTH_RATE_LIMIT);
		if (!comboCheck.allowed) {
			// Phase 3: Propagate block to related keys
			await Promise.all([
				blockIdentifier(env.RATE_LIMIT_KV, keyIp, PASSKEY_AUTH_RATE_LIMIT),
				blockIdentifier(env.RATE_LIMIT_KV, keyUser, PASSKEY_AUTH_RATE_LIMIT),
			]);

			const retryAfter =
				comboCheck.blockedUntil != null
					? Math.max(1, Math.ceil((comboCheck.blockedUntil - Date.now()) / 1000))
					: Math.max(1, Math.ceil(PASSKEY_AUTH_RATE_LIMIT.blockDurationMs / 1000));

			return new Response(JSON.stringify({ error: 'Too many authentication attempts' }), {
				status: 429,
				headers: {
					'Content-Type': 'application/json',
					'Retry-After': retryAfter.toString(),
				},
			});
		}

		// Normalize credential from client JSON format
		const normalizedCredential = normalizeWebAuthnCredential(credential);

		// Get credential from storage
		// Extract credential ID from response
		const credentialIdB64 =
			typeof normalizedCredential?.rawId === 'string'
				? normalizedCredential.rawId
				: base64urlEncode(new Uint8Array(normalizedCredential.rawId));

		const storedKey = `passkey:${username}:${credentialIdB64}`;
		const storedDataRaw = await kv.get(storedKey);

		if (!storedDataRaw) {
			return new Response(JSON.stringify({ error: 'Authentication failed' }), {
				status: 401,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		const storedCredential = JSON.parse(storedDataRaw) as PasskeyCredential;

		// Verify authentication response
		const origin = request.headers.get('Origin') || env.WORKER_URL;
		const rpId = new URL(origin).hostname;
		const expectedChallenge = base64urlDecode(challengeRecord.challenge);
		const verificationResult = await verifyAuthenticationResponse(
			normalizedCredential,
			expectedChallenge,
			storedCredential,
			rpId,
			origin,
		);

		// Delete challenge
		await deleteChallenge(kv, challengeId);

		// Update counter
		storedCredential.counter = verificationResult.newCounter;
		await kv.put(storedKey, JSON.stringify(storedCredential));

		// Reset rate limits on successful authentication
		const resetPromises = [resetRateLimit(env.RATE_LIMIT_KV, keyIp)];
		if (keyUser) resetPromises.push(resetRateLimit(env.RATE_LIMIT_KV, keyUser));
		if (keyCombo) resetPromises.push(resetRateLimit(env.RATE_LIMIT_KV, keyCombo));
		await Promise.all(resetPromises);

		// Generate JWT tokens
		const accessToken = await generateAccessToken(username, env.JWT_SECRET);
		const refreshToken = await generateRefreshToken(username, env.JWT_SECRET);

		return new Response(
			JSON.stringify({
				success: true,
				accessToken,
				refreshToken,
				user: { username },
				expiresIn: 900, // 15 minutes
			}),
			{
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			},
		);
	} catch (error) {
		if (error instanceof Response) {
			return error;
		}
		console.error('Passkey auth finish error:', error);
		return new Response(
			JSON.stringify({
				error: 'Authentication verification failed',
				details: error instanceof Error ? error.message : 'Unknown error',
			}),
			{
				status: 401,
				headers: { 'Content-Type': 'application/json' },
			},
		);
	}
}

/**
 * List user's passkeys
 *
 * GET /auth/passkeys
 * Requires authentication
 */
export async function handlePasskeyList(request: Request, env: Env, authContext: AuthContext): Promise<Response> {
	try {
		const username = authContext.userId;
		const kv = getAuthKV(env);

		const passkeys = await listUserPasskeys(kv, username);

		const passkeyList: PasskeyListItem[] = passkeys.map((p) => ({
			id: p.credentialId,
			name: p.name,
			createdAt: p.createdAt,
		}));

		return new Response(
			JSON.stringify({
				passkeys: passkeyList,
				count: passkeyList.length,
			}),
			{
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			},
		);
	} catch (error) {
		console.error('Passkey list error:', error);
		return new Response(JSON.stringify({ error: 'Internal server error' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}

/**
 * Delete a passkey
 *
 * DELETE /auth/passkey/:credentialId
 * Requires authentication
 */
export async function handlePasskeyDelete(
	request: Request,
	env: Env,
	authContext: AuthContext,
	credentialId: string,
): Promise<Response> {
	try {
		const username = authContext.userId;
		const kv = getAuthKV(env);

		const key = `passkey:${username}:${credentialId}`;
		const existing = await kv.get(key);

		if (!existing) {
			return new Response(JSON.stringify({ error: 'Passkey not found' }), {
				status: 404,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		await kv.delete(key);

		return new Response(
			JSON.stringify({
				success: true,
				deletedId: credentialId,
				message: 'Passkey deleted successfully',
			}),
			{
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			},
		);
	} catch (error) {
		console.error('Passkey delete error:', error);
		return new Response(JSON.stringify({ error: 'Internal server error' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}

/**
 * List all passkeys for a user
 *
 * @param kv - KV namespace
 * @param username - User ID
 * @returns Array of passkey credentials
 */
async function listUserPasskeys(kv: KVNamespace, username: string): Promise<PasskeyCredential[]> {
	// KV doesn't support prefix listing, so we need to use list() with prefix
	const prefix = `passkey:${username}:`;
	const list = await kv.list({ prefix });

	const passkeys: PasskeyCredential[] = [];
	for (const key of list.keys) {
		const data = await kv.get(key.name);
		if (data) {
			try {
				passkeys.push(JSON.parse(data) as PasskeyCredential);
			} catch {
				// Skip invalid data
			}
		}
	}

	return passkeys;
}

/**
 * Normalize WebAuthn credential from client JSON format to binary format
 *
 * Converts base64url-encoded strings back to ArrayBuffer/Uint8Array
 * for verification functions that expect binary data
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function normalizeWebAuthnCredential(credential: any): any {
	if (!credential || typeof credential !== 'object') {
		return credential;
	}

	const normalized = { ...credential, response: { ...credential.response } };

	const decodeField = (value: unknown): Uint8Array | ArrayBuffer | undefined => {
		if (!value) {
			return undefined;
		}
		if (typeof value === 'string') {
			return base64urlDecode(value);
		}
		if (value instanceof Uint8Array || value instanceof ArrayBuffer) {
			return value;
		}
		return undefined;
	};

	// Decode rawId
	const rawIdDecoded = decodeField(normalized.rawId);
	if (rawIdDecoded) {
		normalized.rawId = rawIdDecoded;
	}

	// Decode response fields
	const fields = ['clientDataJSON', 'attestationObject', 'authenticatorData', 'signature'] as const;
	for (const field of fields) {
		const decoded = decodeField(normalized.response?.[field]);
		if (decoded) {
			normalized.response[field] = decoded;
		}
	}

	return normalized;
}
