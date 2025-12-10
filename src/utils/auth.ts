// 文件名：src/utils/auth.ts
import type { Env, AuthContext } from '../types';
import { verifyPassword } from './crypto';
import { verifyToken, extractToken, generateAccessToken, generateRefreshToken, type JWTPayload } from './jwt';
import { checkRateLimit, resetRateLimit, getClientIdentifier, LOGIN_RATE_LIMIT } from './rateLimit';

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

		// Rate limiting for login attempts
		const identifier = `login:${username}:${getClientIdentifier(request)}`;
		const rateLimit = await checkRateLimit(env.RATE_LIMIT_KV, identifier, LOGIN_RATE_LIMIT);

		if (!rateLimit.allowed) {
			// Rate limited - block the request
			return null;
		}

		// Verify password hash
		const isValid = await verifyPassword(password, env.PASSWORD_HASH);

		if (!isValid) {
			// Invalid password - don't reset rate limit
			return null;
		}

		// Successful authentication - reset rate limit
		await resetRateLimit(env.RATE_LIMIT_KV, identifier);

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
		const body = await request.json<{ username: string; password: string }>();
		const { username, password } = body;

		if (!username || !password) {
			return new Response(JSON.stringify({ error: 'Missing username or password' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Rate limiting
		const identifier = `login:${username}:${getClientIdentifier(request)}`;
		const rateLimit = await checkRateLimit(env.RATE_LIMIT_KV, identifier, LOGIN_RATE_LIMIT);

		if (!rateLimit.allowed) {
			const retryAfter = rateLimit.blockedUntil ? Math.ceil((rateLimit.blockedUntil - Date.now()) / 1000) : 3600;
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
		const isValid = await verifyPassword(password, env.PASSWORD_HASH);
		if (!isValid) {
			return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
				status: 401,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Success - reset rate limit
		await resetRateLimit(env.RATE_LIMIT_KV, identifier);

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
		const body = await request.json<{ refreshToken: string }>();
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
