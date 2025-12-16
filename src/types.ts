// 文件名：src/types.ts

import type { PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions } from './webauthn.d';

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
	TOTP_KV: KVNamespace; // For TOTP 2FA data storage
	AUTH_KV?: KVNamespace; // Optional: For WebAuthn passkey data (falls back to TOTP_KV if not set)

	// Configuration
	WORKER_URL: string; // Worker's own URL for CORS validation
	MAX_FILE_SIZE?: string; // Optional: maximum file size in bytes (default: 100MB)
	STORAGE_QUOTA?: string; // Optional: total storage quota in bytes (default: 10GB)
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

/**
 * Two-Factor Authentication data structure
 *
 * Stored in TOTP_KV with key: `user:totp:${username}`
 */
export interface TwoFactorData {
	// TOTP configuration
	totpSecret: string; // Base32-encoded TOTP secret
	totpEnabled: boolean; // Whether 2FA is currently enabled

	// Recovery codes (hashed with PBKDF2, same as passwords)
	recoveryCodes: string[]; // Array of hashed recovery codes

	// Metadata
	enabledAt?: number; // Timestamp when 2FA was enabled
	lastUsedAt?: number; // Timestamp of last successful 2FA verification
}

/**
 * Partial authentication token payload
 *
 * Issued after successful password verification but before 2FA verification.
 * Only valid for accessing /auth/2fa/verify endpoint.
 */
export interface PartialAuthToken {
	userId: string;
	partial: true; // Indicates this is a partial token
	iat: number; // Issued at timestamp
	exp: number; // Expiration timestamp (short-lived: 5 minutes)
}

/**
 * WebAuthn Passkey Credential
 *
 * Stored in KV with key: `passkey:${userId}:${credentialId}`
 * Represents a registered authenticator (fingerprint, Face ID, hardware key, etc.)
 */
export interface PasskeyCredential {
	/** WebAuthn Credential ID (base64url encoded) */
	credentialId: string;

	/** Public key in COSE format (base64url encoded) */
	publicKey: string;

	/** Signature counter for replay protection (must increment with each use) */
	counter: number;

	/** User-friendly name for this passkey (e.g., "iPhone 15", "YubiKey") */
	name: string;

	/** Creation timestamp in milliseconds */
	createdAt: number;
}

/**
 * WebAuthn Challenge Record
 *
 * Stored in KV with key: `challenge:${challengeId}` and TTL of 5 minutes
 * Used to verify registration/authentication ceremony
 */
export interface ChallengeRecord {
	/** Random challenge bytes (base64url encoded) */
	challenge: string;

	/** Associated user ID */
	userId: string;

	/** Expiration timestamp in milliseconds */
	expiresAt: number;
}

// ==================== WebAuthn API Types ====================

/**
 * Response for passkey registration start
 * Contains options for navigator.credentials.create()
 */
export interface PasskeyRegisterStartResponse {
	/** PublicKey credential creation options */
	options: PublicKeyCredentialCreationOptions;

	/** Challenge ID for verification in finish step */
	challengeId: string;
}

/**
 * Request for passkey registration finish
 * Contains attestation response from authenticator
 */
export interface PasskeyRegisterFinishRequest {
	/** Serialized PublicKeyCredential from navigator.credentials.create() */
	credential: unknown;

	/** Challenge ID from start step */
	challengeId: string;

	/** Optional friendly name for this passkey */
	name?: string;
}

/**
 * Request for passkey authentication start
 * Requires username to fetch allowed credentials
 */
export interface PasskeyAuthStartRequest {
	/** Username to authenticate */
	username: string;
}

/**
 * Response for passkey authentication start
 * Contains options for navigator.credentials.get()
 */
export interface PasskeyAuthStartResponse {
	/** PublicKey credential request options */
	options: PublicKeyCredentialRequestOptions;

	/** Challenge ID for verification in finish step */
	challengeId: string;
}

/**
 * Request for passkey authentication finish
 * Contains assertion response from authenticator
 */
export interface PasskeyAuthFinishRequest {
	/** Serialized PublicKeyCredential from navigator.credentials.get() */
	credential: unknown;

	/** Challenge ID from start step */
	challengeId: string;
}

/**
 * Passkey list item for management UI
 */
export interface PasskeyListItem {
	/** Credential ID (unique identifier) */
	id: string;

	/** User-friendly name */
	name: string;

	/** Creation timestamp */
	createdAt: number;
}

/**
 * Response for passkey deletion
 */
export interface PasskeyDeleteResponse {
	/** Whether deletion was successful */
	success: boolean;

	/** ID of deleted passkey */
	deletedId: string;
}
