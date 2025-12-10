/**
 * Rate limiting utilities using Workers KV
 *
 * This module provides rate limiting functionality to protect against
 * brute force attacks and abuse. It uses Workers KV for distributed
 * state tracking across edge locations.
 *
 * Features:
 * - Configurable attempt limits and time windows
 * - Automatic blocking after exceeding limits
 * - TTL-based automatic cleanup
 * - Per-identifier tracking (IP, username, etc.)
 */

/**
 * Rate limit configuration
 */
export interface RateLimitConfig {
	maxAttempts: number; // Maximum attempts allowed in the time window
	windowMs: number; // Time window in milliseconds
	blockDurationMs: number; // How long to block after exceeding limit
}

/**
 * Rate limit state stored in KV
 */
interface RateLimitState {
	attempts: number; // Number of attempts in current window
	windowStart: number; // Start time of current window (Unix timestamp in ms)
	blockedUntil?: number; // When the block expires (Unix timestamp in ms)
}

/**
 * Result of rate limit check
 */
export interface RateLimitResult {
	allowed: boolean; // Whether the request is allowed
	remainingAttempts: number; // Remaining attempts before block
	resetAt?: number; // When the window resets (Unix timestamp in ms)
	blockedUntil?: number; // When the block expires (Unix timestamp in ms)
}

/**
 * Default rate limit configuration for login attempts
 */
export const LOGIN_RATE_LIMIT: RateLimitConfig = {
	maxAttempts: 5,
	windowMs: 15 * 60 * 1000, // 15 minutes
	blockDurationMs: 60 * 60 * 1000, // 1 hour
};

/**
 * Default rate limit configuration for API requests
 */
export const API_RATE_LIMIT: RateLimitConfig = {
	maxAttempts: 100,
	windowMs: 60 * 1000, // 1 minute
	blockDurationMs: 5 * 60 * 1000, // 5 minutes
};

/**
 * Check if a request should be rate limited
 *
 * This function implements a sliding window rate limiter with automatic blocking.
 * It tracks attempts per identifier (e.g., IP address or username) and blocks
 * requests that exceed the configured limits.
 *
 * @param kv - KV namespace for storing rate limit state
 * @param identifier - Unique identifier for rate limiting (e.g., IP address, username)
 * @param config - Rate limit configuration
 * @returns Rate limit result with allowed status and remaining attempts
 *
 * @example
 * const result = await checkRateLimit(
 *   env.RATE_LIMIT_KV,
 *   request.headers.get('CF-Connecting-IP') || 'unknown',
 *   LOGIN_RATE_LIMIT
 * );
 *
 * if (!result.allowed) {
 *   return new Response('Too many attempts', { status: 429 });
 * }
 */
export async function checkRateLimit(
	kv: KVNamespace,
	identifier: string,
	config: RateLimitConfig = LOGIN_RATE_LIMIT
): Promise<RateLimitResult> {
	const key = `ratelimit:${identifier}`;
	const now = Date.now();

	// Get current state from KV
	const stateJson = await kv.get(key);
	const state: RateLimitState | null = stateJson ? JSON.parse(stateJson) : null;

	// Check if currently blocked
	if (state?.blockedUntil && state.blockedUntil > now) {
		return {
			allowed: false,
			remainingAttempts: 0,
			blockedUntil: state.blockedUntil,
		};
	}

	// Check if window has expired
	if (!state || now - state.windowStart > config.windowMs) {
		// Start new window with first attempt
		const newState: RateLimitState = {
			attempts: 1,
			windowStart: now,
		};

		await kv.put(key, JSON.stringify(newState), {
			expirationTtl: Math.floor(config.windowMs / 1000),
		});

		return {
			allowed: true,
			remainingAttempts: config.maxAttempts - 1,
			resetAt: now + config.windowMs,
		};
	}

	// Check if exceeded max attempts
	if (state.attempts >= config.maxAttempts) {
		// Block the identifier
		const blockedUntil = now + config.blockDurationMs;
		const blockedState: RateLimitState = {
			...state,
			blockedUntil,
		};

		await kv.put(key, JSON.stringify(blockedState), {
			expirationTtl: Math.floor(config.blockDurationMs / 1000),
		});

		return {
			allowed: false,
			remainingAttempts: 0,
			blockedUntil,
		};
	}

	// Increment attempt counter
	const updatedState: RateLimitState = {
		attempts: state.attempts + 1,
		windowStart: state.windowStart,
	};

	await kv.put(key, JSON.stringify(updatedState), {
		expirationTtl: Math.floor(config.windowMs / 1000),
	});

	return {
		allowed: true,
		remainingAttempts: config.maxAttempts - updatedState.attempts,
		resetAt: state.windowStart + config.windowMs,
	};
}

/**
 * Record a successful operation and reset rate limit
 *
 * Call this after successful authentication to reset the attempt counter.
 *
 * @param kv - KV namespace for storing rate limit state
 * @param identifier - Unique identifier for rate limiting
 *
 * @example
 * // After successful login
 * await resetRateLimit(env.RATE_LIMIT_KV, username);
 */
export async function resetRateLimit(kv: KVNamespace, identifier: string): Promise<void> {
	const key = `ratelimit:${identifier}`;
	await kv.delete(key);
}

/**
 * Get current rate limit status without incrementing counter
 *
 * Useful for displaying rate limit information to users.
 *
 * @param kv - KV namespace for storing rate limit state
 * @param identifier - Unique identifier for rate limiting
 * @param config - Rate limit configuration
 * @returns Current rate limit status
 *
 * @example
 * const status = await getRateLimitStatus(env.RATE_LIMIT_KV, ip, LOGIN_RATE_LIMIT);
 * console.log(`${status.remainingAttempts} attempts remaining`);
 */
export async function getRateLimitStatus(
	kv: KVNamespace,
	identifier: string,
	config: RateLimitConfig = LOGIN_RATE_LIMIT
): Promise<RateLimitResult> {
	const key = `ratelimit:${identifier}`;
	const now = Date.now();

	const stateJson = await kv.get(key);
	const state: RateLimitState | null = stateJson ? JSON.parse(stateJson) : null;

	// Check if currently blocked
	if (state?.blockedUntil && state.blockedUntil > now) {
		return {
			allowed: false,
			remainingAttempts: 0,
			blockedUntil: state.blockedUntil,
		};
	}

	// Check if window has expired
	if (!state || now - state.windowStart > config.windowMs) {
		return {
			allowed: true,
			remainingAttempts: config.maxAttempts,
			resetAt: now + config.windowMs,
		};
	}

	// Within active window
	const remaining = Math.max(0, config.maxAttempts - state.attempts);

	return {
		allowed: remaining > 0,
		remainingAttempts: remaining,
		resetAt: state.windowStart + config.windowMs,
	};
}

/**
 * Force an identifier into blocked state without incrementing attempts
 *
 * Used for coordinated blocking across multiple rate limit keys (e.g., IP, user, user+IP).
 * When one key reaches the threshold, this function can block the related keys to maintain
 * consistent enforcement across all dimensions.
 *
 * @param kv - KV namespace for storing rate limit state
 * @param identifier - Unique identifier to block
 * @param config - Rate limit configuration
 *
 * @example
 * // When user+IP combo is blocked, also block the user key
 * await blockIdentifier(env.RATE_LIMIT_KV, `login:user:${username}`, LOGIN_RATE_LIMIT);
 */
export async function blockIdentifier(
	kv: KVNamespace,
	identifier: string,
	config: RateLimitConfig = LOGIN_RATE_LIMIT
): Promise<void> {
	const key = `ratelimit:${identifier}`;
	const now = Date.now();
	const blockedUntil = now + config.blockDurationMs;

	const state: RateLimitState = {
		attempts: config.maxAttempts,
		windowStart: now,
		blockedUntil,
	};

	await kv.put(key, JSON.stringify(state), {
		expirationTtl: Math.floor(config.blockDurationMs / 1000),
	});
}

/**
 * Get client identifier for rate limiting
 *
 * Extracts the best available identifier from the request:
 * 1. CF-Connecting-IP (Cloudflare real IP)
 * 2. X-Forwarded-For (proxy chain)
 * 3. X-Real-IP (alternative proxy header)
 * 4. 'unknown' (fallback)
 *
 * @param request - Incoming request
 * @returns Client identifier suitable for rate limiting
 *
 * @example
 * const identifier = getClientIdentifier(request);
 * const result = await checkRateLimit(env.RATE_LIMIT_KV, identifier);
 */
export function getClientIdentifier(request: Request): string {
	// Cloudflare provides real IP in CF-Connecting-IP
	const cfIp = request.headers.get('CF-Connecting-IP');
	if (cfIp) {
		return cfIp;
	}

	// Fallback to X-Forwarded-For (take first IP)
	const xForwardedFor = request.headers.get('X-Forwarded-For');
	if (xForwardedFor) {
		return xForwardedFor.split(',')[0].trim();
	}

	// Fallback to X-Real-IP
	const xRealIp = request.headers.get('X-Real-IP');
	if (xRealIp) {
		return xRealIp;
	}

	// Last resort fallback
	return 'unknown';
}
