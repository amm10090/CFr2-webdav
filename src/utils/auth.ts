// 文件名：src/utils/auth.ts
import type { Env, AuthContext } from '../types';
import { verifyPassword } from './crypto';
import { verifyToken, extractToken, generateAccessToken, generateRefreshToken } from './jwt';
import {
	checkRateLimit,
	getRateLimitStatus,
	resetRateLimit,
	blockIdentifier,
	getClientIdentifier,
	LOGIN_RATE_LIMIT,
} from './rateLimit';

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

		// Generate tokens
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
