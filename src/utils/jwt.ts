/**
 * JWT (JSON Web Token) utilities using Web Crypto API
 *
 * This module provides JWT token generation and verification using HMAC-SHA256.
 * Supports both access tokens (short-lived) and refresh tokens (long-lived).
 *
 * Token Format: header.payload.signature (Base64URL encoded)
 * Algorithm: HS256 (HMAC with SHA-256)
 */

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

/**
 * JWT payload structure
 */
export interface JWTPayload {
	sub: string; // Subject (user identifier)
	iat: number; // Issued at (Unix timestamp)
	exp: number; // Expiration time (Unix timestamp)
	type: 'access' | 'refresh'; // Token type
}

/**
 * JWT header structure (fixed for HS256)
 */
interface JWTHeader {
	alg: 'HS256';
	typ: 'JWT';
}

// Token lifetimes
const ACCESS_TOKEN_LIFETIME = 15 * 60; // 15 minutes in seconds
const REFRESH_TOKEN_LIFETIME = 7 * 24 * 60 * 60; // 7 days in seconds

/**
 * Base64URL encode a Uint8Array
 * Standard Base64 encoding with URL-safe characters (- and _ instead of + and /)
 * and padding removed
 */
function base64urlEncode(buffer: Uint8Array): string {
	const base64 = btoa(String.fromCharCode(...buffer));
	return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Base64URL decode to Uint8Array
 * @throws {Error} If base64url string is invalid
 */
function base64urlDecode(base64url: string): Uint8Array {
	try {
		// Restore padding
		const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
		const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/') + padding;

		return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
	} catch {
		throw new Error('Invalid Base64URL encoding');
	}
}

/**
 * Base64URL encode a JSON object
 */
function base64urlEncodeJSON(obj: unknown): string {
	const json = JSON.stringify(obj);
	const buffer = TEXT_ENCODER.encode(json);
	return base64urlEncode(buffer);
}

/**
 * Base64URL decode to a JSON object
 */
function base64urlDecodeJSON<T>(base64url: string): T {
	const buffer = base64urlDecode(base64url);
	const json = TEXT_DECODER.decode(buffer);
	return JSON.parse(json) as T;
}

/**
 * Generate HMAC-SHA256 signature for JWT
 *
 * @param data - Data to sign (header.payload)
 * @param secret - Secret key for HMAC
 * @returns Base64URL encoded signature
 */
async function sign(data: string, secret: string): Promise<string> {
	const key = await crypto.subtle.importKey(
		'raw',
		TEXT_ENCODER.encode(secret),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign']
	);

	const signature = await crypto.subtle.sign('HMAC', key, TEXT_ENCODER.encode(data));

	return base64urlEncode(new Uint8Array(signature));
}

/**
 * Verify HMAC-SHA256 signature for JWT
 *
 * @param data - Data that was signed (header.payload)
 * @param signature - Base64URL encoded signature to verify
 * @param secret - Secret key for HMAC
 * @returns True if signature is valid, false if invalid or malformed
 */
async function verify(data: string, signature: string, secret: string): Promise<boolean> {
	try {
		const key = await crypto.subtle.importKey(
			'raw',
			TEXT_ENCODER.encode(secret),
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['verify']
		);

		const signatureBuffer = base64urlDecode(signature);
		const isValid = await crypto.subtle.verify('HMAC', key, signatureBuffer, TEXT_ENCODER.encode(data));

		return isValid;
	} catch {
		// Invalid base64url encoding or other error
		return false;
	}
}

/**
 * Create a JWT token
 *
 * @param payload - JWT payload
 * @param secret - Secret key for signing
 * @returns JWT token string (header.payload.signature)
 */
async function createJWT(payload: JWTPayload, secret: string): Promise<string> {
	const header: JWTHeader = {
		alg: 'HS256',
		typ: 'JWT',
	};

	const encodedHeader = base64urlEncodeJSON(header);
	const encodedPayload = base64urlEncodeJSON(payload);

	const data = `${encodedHeader}.${encodedPayload}`;
	const signature = await sign(data, secret);

	return `${data}.${signature}`;
}

/**
 * Generate an access token for a user
 *
 * Access tokens are short-lived (15 minutes) and used for API requests.
 *
 * @param userId - User identifier
 * @param secret - Secret key for signing
 * @returns JWT access token
 *
 * @example
 * const token = await generateAccessToken("user123", env.JWT_SECRET);
 * // Use in Authorization header: `Bearer ${token}`
 */
export async function generateAccessToken(userId: string, secret: string): Promise<string> {
	const now = Math.floor(Date.now() / 1000);

	const payload: JWTPayload = {
		sub: userId,
		iat: now,
		exp: now + ACCESS_TOKEN_LIFETIME,
		type: 'access',
	};

	return createJWT(payload, secret);
}

/**
 * Generate a refresh token for a user
 *
 * Refresh tokens are long-lived (7 days) and used to obtain new access tokens.
 *
 * @param userId - User identifier
 * @param secret - Secret key for signing
 * @returns JWT refresh token
 *
 * @example
 * const token = await generateRefreshToken("user123", env.JWT_SECRET);
 * // Store securely and use to get new access tokens
 */
export async function generateRefreshToken(userId: string, secret: string): Promise<string> {
	const now = Math.floor(Date.now() / 1000);

	const payload: JWTPayload = {
		sub: userId,
		iat: now,
		exp: now + REFRESH_TOKEN_LIFETIME,
		type: 'refresh',
	};

	return createJWT(payload, secret);
}

/**
 * Verify and decode a JWT token
 *
 * @param token - JWT token to verify
 * @param secret - Secret key for verification
 * @returns Decoded payload if valid, null if invalid, expired, or malformed
 *
 * @example
 * const payload = await verifyToken(token, env.JWT_SECRET);
 * if (payload) {
 *   console.log(`Token valid for user: ${payload.sub}`);
 * } else {
 *   console.log("Token invalid or expired");
 * }
 */
export async function verifyToken(token: string, secret: string): Promise<JWTPayload | null> {
	// Split token into parts
	const parts = token.split('.');
	if (parts.length !== 3) {
		return null; // Malformed token
	}

	const [encodedHeader, encodedPayload, signature] = parts;

	// Verify signature (returns false for malformed signature)
	const data = `${encodedHeader}.${encodedPayload}`;
	const isValid = await verify(data, signature, secret);

	if (!isValid) {
		return null; // Invalid signature or malformed
	}

	// Decode header and validate algorithm
	let header: JWTHeader;
	try {
		header = base64urlDecodeJSON<JWTHeader>(encodedHeader);
	} catch {
		return null; // Invalid header encoding
	}

	if (header.alg !== 'HS256' || header.typ !== 'JWT') {
		return null; // Unsupported algorithm
	}

	// Decode payload
	let payload: JWTPayload;
	try {
		payload = base64urlDecodeJSON<JWTPayload>(encodedPayload);
	} catch {
		return null; // Invalid payload encoding
	}

	// Validate payload structure
	if (
		typeof payload.sub !== 'string' ||
		typeof payload.iat !== 'number' ||
		typeof payload.exp !== 'number' ||
		(payload.type !== 'access' && payload.type !== 'refresh')
	) {
		return null; // Invalid payload structure
	}

	// Check expiration
	const now = Math.floor(Date.now() / 1000);
	if (payload.exp <= now) {
		return null; // Token expired
	}

	// Check issued-at time is not in the future (clock skew tolerance: 5 minutes)
	if (payload.iat > now + 300) {
		return null; // Time travel detected
	}

	return payload;
}

/**
 * Extract token from Authorization header
 *
 * Supports both "Bearer <token>" and just "<token>" formats.
 *
 * @param authHeader - Authorization header value
 * @returns Token string or null if invalid format
 *
 * @example
 * const token = extractToken(request.headers.get('Authorization'));
 * if (token) {
 *   const payload = await verifyToken(token, env.JWT_SECRET);
 * }
 */
export function extractToken(authHeader: string | null): string | null {
	if (!authHeader) {
		return null;
	}

	// Support "Bearer <token>" format
	if (authHeader.startsWith('Bearer ')) {
		return authHeader.slice(7).trim();
	}

	// Support raw token format
	if (authHeader.length > 0 && !authHeader.includes(' ')) {
		return authHeader;
	}

	return null;
}
