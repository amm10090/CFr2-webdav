import { Env } from '../types';
import { handleWebDAV } from './webdavHandler';
import {
	authenticate,
	createUnauthorizedResponse,
	handleLogin,
	handleRefresh,
	handle2FASetup,
	handle2FAVerifySetup,
	handle2FADisable,
	handle2FAStatus,
	handle2FAVerify,
	handle2FARegenerateRecoveryCodes,
	handlePasskeyRegisterStart,
	handlePasskeyRegisterFinish,
	handlePasskeyAuthStart,
	handlePasskeyAuthFinish,
	handlePasskeyList,
	handlePasskeyDelete,
} from '../utils/auth';
import { setCORSHeaders } from '../utils/cors';
import { logger } from '../utils/logger';
import { generateHTML, generateLoginHTML } from '../utils/templates';

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

		// Handle 2FA verification during login (no full auth required, partial token only)
		if (url.pathname === '/auth/2fa/verify' && request.method === 'POST') {
			const response = await handle2FAVerify(request, env);
			setCORSHeaders(response, request, env);
			return response;
		}

		// Passkey authentication endpoints (no auth required)
		if (url.pathname === '/auth/passkey/authenticate/start' && request.method === 'POST') {
			const response = await handlePasskeyAuthStart(request, env);
			setCORSHeaders(response, request, env);
			return response;
		}

		if (url.pathname === '/auth/passkey/authenticate/finish' && request.method === 'POST') {
			const response = await handlePasskeyAuthFinish(request, env);
			setCORSHeaders(response, request, env);
			return response;
		}

		// Handle CORS preflight (OPTIONS) - no authentication required
		if (request.method === 'OPTIONS') {
			const response = new Response(null, { status: 204 });
			setCORSHeaders(response, request, env);
			return response;
		}


	// Handle login page (no authentication required)
	if (url.pathname === '/login' && request.method === 'GET') {
		// If already authenticated, redirect to home page
		const authContext = await authenticate(request, env);
		if (authContext) {
			const response = new Response(null, {
				status: 302,
				headers: { Location: '/' },
			});
			setCORSHeaders(response, request, env);
			return response;
		}

		// Show login page
		const html = generateLoginHTML(Boolean(env.DEMO_MODE));
		const response = new Response(html, {
			status: 200,
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		});
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
					// Redirect unauthenticated browser users to login page
					const response = new Response(null, {
						status: 302,
						headers: { Location: '/login' },
					});
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

		// Handle 2FA management endpoints (require full authentication)
		if (url.pathname === '/auth/2fa/setup' && request.method === 'POST') {
			const response = await handle2FASetup(request, env, authContext);
			setCORSHeaders(response, request, env);
			return response;
		}

		if (url.pathname === '/auth/2fa/verify-setup' && request.method === 'POST') {
			const response = await handle2FAVerifySetup(request, env, authContext);
			setCORSHeaders(response, request, env);
			return response;
		}

		if (url.pathname === '/auth/2fa/disable' && request.method === 'POST') {
			const response = await handle2FADisable(request, env, authContext);
			setCORSHeaders(response, request, env);
			return response;
		}

		if (url.pathname === '/auth/2fa/status' && request.method === 'GET') {
			const response = await handle2FAStatus(request, env, authContext);
			setCORSHeaders(response, request, env);
			return response;
		}

		if (url.pathname === '/auth/2fa/recovery-codes/regenerate' && request.method === 'POST') {
			const response = await handle2FARegenerateRecoveryCodes(request, env, authContext);
			setCORSHeaders(response, request, env);
			return response;
		}

		// Passkey management endpoints (require authentication)
		if (url.pathname === '/auth/passkey/register/start' && request.method === 'POST') {
			const response = await handlePasskeyRegisterStart(request, env, authContext);
			setCORSHeaders(response, request, env);
			return response;
		}

		if (url.pathname === '/auth/passkey/register/finish' && request.method === 'POST') {
			const response = await handlePasskeyRegisterFinish(request, env, authContext);
			setCORSHeaders(response, request, env);
			return response;
		}

		if (url.pathname === '/auth/passkeys' && request.method === 'GET') {
			const response = await handlePasskeyList(request, env, authContext);
			setCORSHeaders(response, request, env);
			return response;
		}

		if (url.pathname.startsWith('/auth/passkey/') && request.method === 'DELETE') {
			const credentialId = url.pathname.split('/').pop();
			if (credentialId) {
				const response = await handlePasskeyDelete(request, env, authContext, credentialId);
				setCORSHeaders(response, request, env);
				return response;
			}
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
