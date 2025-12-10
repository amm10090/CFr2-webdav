// 文件名：src/utils/cors.ts
import type { Env } from '../types';

/**
 * Set CORS headers with origin whitelist validation
 *
 * This function implements secure CORS by only allowing requests from
 * explicitly whitelisted origins (the Worker's own domain).
 *
 * Security considerations:
 * - Never reflects arbitrary origins (prevents CORS bypass attacks)
 * - Uses Vary header for proper caching with multiple origins
 * - Only sets Access-Control-Allow-Credentials with validated origins
 *
 * @param response - Response to add CORS headers to
 * @param request - Incoming request to validate origin from
 * @param env - Environment bindings containing WORKER_URL
 */
export function setCORSHeaders(response: Response, request: Request, env: Env): void {
	const origin = request.headers.get('Origin');

	// Build allowed origins list from environment
	const allowedOrigins: string[] = [];

	// Add Worker's own URL if configured
	if (env.WORKER_URL) {
		allowedOrigins.push(env.WORKER_URL);
		// Also allow without trailing slash
		if (env.WORKER_URL.endsWith('/')) {
			allowedOrigins.push(env.WORKER_URL.slice(0, -1));
		} else {
			allowedOrigins.push(env.WORKER_URL + '/');
		}
	}

	// Add localhost for development (optional, comment out for production)
	if (env.DEMO_MODE) {
		allowedOrigins.push('http://localhost:8787');
		allowedOrigins.push('http://127.0.0.1:8787');
		allowedOrigins.push('http://localhost:3000');
		allowedOrigins.push('http://127.0.0.1:3000');
	}

	// Normalize origins by removing trailing slashes for comparison
	const normalizedAllowed = new Set(allowedOrigins.map((o) => o.replace(/\/$/, '')));
	const normalizedOrigin = origin ? origin.replace(/\/$/, '') : null;

	// Only set Access-Control-Allow-Origin if origin is in whitelist
	if (normalizedOrigin && normalizedAllowed.has(normalizedOrigin)) {
		response.headers.set('Access-Control-Allow-Origin', origin);
		response.headers.set('Access-Control-Allow-Credentials', 'true');
	}

	// Always set Vary header for proper caching behavior
	// This tells caches that responses vary based on the Origin header
	response.headers.set('Vary', 'Origin');

	// Set other CORS headers (these are safe to set regardless of origin)
	response.headers.set('Access-Control-Allow-Methods', 'OPTIONS, PROPFIND, MKCOL, GET, HEAD, PUT, COPY, MOVE, DELETE');
	response.headers.set(
		'Access-Control-Allow-Headers',
		'Authorization, Content-Type, Depth, Overwrite, Destination, Range',
	);
	response.headers.set(
		'Access-Control-Expose-Headers',
		'Content-Type, Content-Length, DAV, ETag, Last-Modified, Location, Date, Content-Range',
	);
	response.headers.set('Access-Control-Max-Age', '86400');
}
