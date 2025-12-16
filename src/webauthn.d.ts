/**
 * WebAuthn Type Definitions for Cloudflare Workers
 *
 * These types define the WebAuthn API interfaces used in passkey authentication.
 * Based on W3C Web Authentication specification: https://w3c.github.io/webauthn/
 *
 * Note: These are server-side representations. The actual credential objects
 * are serialized when sent to/from the client.
 */

// ==================== Core WebAuthn Types ====================

/**
 * Descriptor for a public key credential
 * Used to reference an existing credential
 */
export interface PublicKeyCredentialDescriptor {
	/** Type of credential (always "public-key" for WebAuthn) */
	type: 'public-key';

	/** Credential ID as ArrayBuffer */
	id: ArrayBuffer | Uint8Array;

	/** Optional hint about authenticator transport (usb, nfc, ble, internal) */
	transports?: AuthenticatorTransport[];
}

/**
 * Transport mechanism for authenticator
 */
export type AuthenticatorTransport = 'usb' | 'nfc' | 'ble' | 'internal';

/**
 * User verification requirement
 */
export type UserVerificationRequirement = 'required' | 'preferred' | 'discouraged';

/**
 * Attestation conveyance preference
 */
export type AttestationConveyancePreference = 'none' | 'indirect' | 'direct' | 'enterprise';

/**
 * Authenticator attachment modality
 */
export type AuthenticatorAttachment = 'platform' | 'cross-platform';

// ==================== Registration (Create) Types ====================

/**
 * Options for credential creation (registration)
 * Used in navigator.credentials.create()
 */
export interface PublicKeyCredentialCreationOptions {
	/** Random challenge for this ceremony */
	challenge: ArrayBuffer | Uint8Array;

	/** Relying Party (RP) information */
	rp: PublicKeyCredentialRpEntity;

	/** User information */
	user: PublicKeyCredentialUserEntity;

	/** Supported public key algorithms (in order of preference) */
	pubKeyCredParams: PublicKeyCredentialParameters[];

	/** Timeout in milliseconds */
	timeout?: number;

	/** Credentials to exclude (already registered) */
	excludeCredentials?: PublicKeyCredentialDescriptor[];

	/** Authenticator selection criteria */
	authenticatorSelection?: AuthenticatorSelectionCriteria;

	/** Attestation preference */
	attestation?: AttestationConveyancePreference;

	/** Extensions (optional additional data) */
	extensions?: AuthenticationExtensionsClientInputs;
}

/**
 * Relying Party entity information
 */
export interface PublicKeyCredentialRpEntity {
	/** Human-readable RP name */
	name: string;

	/** RP identifier (domain) */
	id?: string;
}

/**
 * User entity information
 */
export interface PublicKeyCredentialUserEntity {
	/** User handle (unique identifier) */
	id: ArrayBuffer | Uint8Array;

	/** Username for display */
	name: string;

	/** User-friendly display name */
	displayName: string;
}

/**
 * Public key algorithm parameters
 */
export interface PublicKeyCredentialParameters {
	/** Credential type */
	type: 'public-key';

	/** COSE algorithm identifier
	 * -7 = ES256 (ECDSA with SHA-256)
	 * -257 = RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
	 */
	alg: number;
}

/**
 * Authenticator selection criteria
 */
export interface AuthenticatorSelectionCriteria {
	/** Preferred authenticator attachment */
	authenticatorAttachment?: AuthenticatorAttachment;

	/** Whether resident key is required */
	requireResidentKey?: boolean;

	/** Whether resident key should be created (newer spec) */
	residentKey?: 'required' | 'preferred' | 'discouraged';

	/** User verification requirement */
	userVerification?: UserVerificationRequirement;
}

// ==================== Authentication (Get) Types ====================

/**
 * Options for credential request (authentication)
 * Used in navigator.credentials.get()
 */
export interface PublicKeyCredentialRequestOptions {
	/** Random challenge for this ceremony */
	challenge: ArrayBuffer | Uint8Array;

	/** Timeout in milliseconds */
	timeout?: number;

	/** RP identifier (domain) */
	rpId?: string;

	/** List of allowed credentials (empty = allow any) */
	allowCredentials?: PublicKeyCredentialDescriptor[];

	/** User verification requirement */
	userVerification?: UserVerificationRequirement;

	/** Extensions (optional additional data) */
	extensions?: AuthenticationExtensionsClientInputs;
}

// ==================== Extension Types ====================

/**
 * Client extension inputs
 * Extensible by adding new properties as needed
 */
export interface AuthenticationExtensionsClientInputs {
	/** App ID extension for U2F compatibility */
	appid?: string;

	/** Credential properties extension */
	credProps?: boolean;

	/** Large blob extension */
	largeBlob?: {
		support?: 'required' | 'preferred';
		read?: boolean;
		write?: ArrayBuffer;
	};

	[key: string]: unknown;
}

// ==================== Algorithm Identifier ====================

/**
 * Web Crypto API algorithm identifier
 * Used for signature verification
 */
export type AlgorithmIdentifier =
	| string
	| {
			name: string;
			hash?: string | { name: string };
			[key: string]: unknown;
	  };
