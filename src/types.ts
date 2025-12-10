// 文件名：src/types.ts

/**
 * Cloudflare Workers environment bindings
 */
export interface Env {
	// R2 Storage
	BUCKET: R2Bucket;
	BUCKET_NAME: string;

	// Authentication (legacy plaintext for backward compatibility)
	USERNAME: string;
	PASSWORD?: string; // Optional: for backward compatibility

	// Secure authentication (use these for new deployments)
	PASSWORD_HASH: string; // v1:iterations:salt:hash format from crypto.hashPassword
	JWT_SECRET: string; // Secret for JWT token signing

	// KV Namespaces
	RATE_LIMIT_KV: KVNamespace; // For rate limiting state
	QUOTA_KV: KVNamespace; // For storage quota tracking

	// Configuration
	WORKER_URL: string; // Worker's own URL for CORS validation
	MAX_FILE_SIZE?: string; // Optional: maximum file size in bytes (default: 100MB)
	STORAGE_QUOTA?: string; // Optional: total storage quota in bytes (default: 10GB)

	// Feature flags
	DEMO_MODE?: string; // Enable demo mode for testing
}

/**
 * Authentication context after successful authentication
 */
export interface AuthContext {
	userId: string; // Authenticated user identifier
	tokenType?: 'access' | 'refresh'; // Type of JWT token used (if JWT auth)
	authenticated: boolean; // Always true for authenticated requests
}

export interface CacheableResponse {
	response: Response;
	expiry: number;
}

export interface WebDAVProps {
	creationdate: string;
	displayname: string | undefined;
	getcontentlanguage: string | undefined;
	getcontentlength: string;
	getcontenttype: string | undefined;
	getetag: string | undefined;
	getlastmodified: string;
	resourcetype: string;
}
