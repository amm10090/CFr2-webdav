import { Env } from '../types';
import { handleWebDAV } from './webdavHandler';
import { authenticate, createUnauthorizedResponse, handleLogin, handleRefresh } from '../utils/auth';
import { setCORSHeaders } from '../utils/cors';
import { logger } from '../utils/logger';
import { generateHTML } from '../utils/templates';

export async function handleRequest(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
	try {
		const url = new URL(request.url);

		// Handle authentication endpoints (no auth required)
		if (url.pathname === '/auth/login' && request.method === 'POST') {
			const response = await handleLogin(request, env);
			setCORSHeaders(response, request, env);
			return response;
		}

		if (url.pathname === '/auth/refresh' && request.method === 'POST') {
			const response = await handleRefresh(request, env);
			setCORSHeaders(response, request, env);
			return response;
		}

		// Handle CORS preflight (OPTIONS) - no authentication required
		if (request.method === 'OPTIONS') {
			const response = new Response(null, { status: 204 });
			setCORSHeaders(response, request, env);
			return response;
		}

		// Handle root path with browser UI
		if (url.pathname === '/' && request.method === 'GET') {
			// Check if it's a browser request (has Accept: text/html)
			const accept = request.headers.get('Accept') || '';
			if (accept.includes('text/html')) {
				// Authenticate first
				const authContext = await authenticate(request, env);
				if (!authContext) {
					const response = createUnauthorizedResponse();
					setCORSHeaders(response, request, env);
					return response;
				}

				// Return the web UI
				const html = generateHTML('R2 WebDAV', [], '/', Boolean(env.DEMO_MODE));
				const response = new Response(html, {
					status: 200,
					headers: { 'Content-Type': 'text/html; charset=utf-8' },
				});
				setCORSHeaders(response, request, env);
				return response;
			}
		}

		// All other requests require authentication
		const authContext = await authenticate(request, env);
		if (!authContext) {
			const response = createUnauthorizedResponse();
			setCORSHeaders(response, request, env);
			return response;
		}

		// Pass authentication context to WebDAV handler
		const response = await handleWebDAV(request, env, authContext);

		setCORSHeaders(response, request, env);
		return response;
	} catch (error) {
		logger.error('Error in request handling:', error);
		const response = new Response('Internal Server Error', { status: 500 });
		setCORSHeaders(response, request, env);
		return response;
	}
}
