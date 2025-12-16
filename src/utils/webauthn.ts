// 文件名：src/utils/webauthn.ts
/**
 * WebAuthn / Passkeys Implementation for CFr2-webdav
 *
 * Implements RFC WebAuthn standard for passwordless authentication using:
 * - Platform authenticators (Touch ID, Face ID, Windows Hello)
 * - Cross-platform authenticators (YubiKey, etc.)
 *
 * Key features:
 * - ES256 and RS256 public key algorithms
 * - Attestation format: none (for simplicity)
 * - Challenge-based ceremony with 5-minute TTL
 * - Counter-based replay protection
 *
 * Dependencies: Web Crypto API (natively supported in Cloudflare Workers)
 */

import type { ChallengeRecord, PasskeyCredential } from '../types';
import type {
	PublicKeyCredentialCreationOptions,
	PublicKeyCredentialRequestOptions,
	AlgorithmIdentifier,
} from '../webauthn.d';

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

// ==================== Base64URL Encoding/Decoding ====================

/**
 * Encode Uint8Array to base64url string
 *
 * Base64URL is base64 with URL-safe characters:
 * - Replace + with -
 * - Replace / with _
 * - Remove padding =
 *
 * @param buffer - Bytes to encode
 * @returns Base64URL encoded string
 */
export function base64urlEncode(buffer: Uint8Array): string {
	let binary = '';
	for (let i = 0; i < buffer.byteLength; i++) {
		binary += String.fromCharCode(buffer[i]);
	}
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

/**
 * Decode base64url string to Uint8Array
 *
 * @param str - Base64URL encoded string
 * @returns Decoded bytes
 */
export function base64urlDecode(str: string): Uint8Array {
	const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
	const base64 = str.replace(/-/g, '+').replace(/_/g, '/') + pad;
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

// ==================== ArrayBuffer Utilities ====================

/**
 * Convert ArrayBuffer to hexadecimal string
 *
 * Useful for debugging and comparison
 *
 * @param buffer - Buffer to convert
 * @returns Hex string
 */
export function bufferToHex(buffer: ArrayBuffer): string {
	const bytes = new Uint8Array(buffer);
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

/**
 * Concatenate multiple Uint8Array into single array
 *
 * @param arrays - Arrays to concatenate
 * @returns Combined array
 */
function concatUint8(...arrays: Uint8Array[]): Uint8Array {
	const total = arrays.reduce((sum, a) => sum + a.length, 0);
	const out = new Uint8Array(total);
	let offset = 0;
	for (const a of arrays) {
		out.set(a, offset);
		offset += a.length;
	}
	return out;
}

// ==================== Challenge Management ====================

/**
 * Generate cryptographically secure 32-byte challenge
 *
 * Challenge is used to prevent replay attacks in WebAuthn ceremony
 *
 * @returns 32-byte random challenge
 */
export function generateChallenge(): Uint8Array {
	const challenge = new Uint8Array(32);
	crypto.getRandomValues(challenge);
	return challenge;
}

/**
 * Save challenge to KV with TTL
 *
 * Challenges are temporary and expire after 5 minutes (default)
 *
 * @param kv - KV namespace
 * @param challengeId - Unique challenge identifier
 * @param challenge - Challenge bytes
 * @param userId - Associated user ID
 * @param ttlSeconds - Time-to-live in seconds (default: 300)
 */
export async function saveChallenge(
	kv: KVNamespace,
	challengeId: string,
	challenge: Uint8Array,
	userId: string,
	ttlSeconds = 300,
): Promise<void> {
	const record: ChallengeRecord = {
		challenge: base64urlEncode(challenge),
		userId,
		expiresAt: Date.now() + ttlSeconds * 1000,
	};
	await kv.put(`challenge:${challengeId}`, JSON.stringify(record), {
		expirationTtl: ttlSeconds,
	});
}

/**
 * Retrieve challenge from KV
 *
 * @param kv - KV namespace
 * @param challengeId - Challenge identifier
 * @returns Challenge record or null if not found/expired
 */
export async function getChallenge(kv: KVNamespace, challengeId: string): Promise<ChallengeRecord | null> {
	const raw = await kv.get(`challenge:${challengeId}`);
	if (!raw) {
		return null;
	}

	try {
		const parsed = JSON.parse(raw) as ChallengeRecord;
		// Double-check expiration (KV TTL should handle this, but be safe)
		if (parsed.expiresAt && parsed.expiresAt < Date.now()) {
			return null;
		}
		return parsed;
	} catch {
		return null;
	}
}

/**
 * Delete challenge from KV
 *
 * Should be called after successful verification to prevent reuse
 *
 * @param kv - KV namespace
 * @param challengeId - Challenge identifier
 */
export async function deleteChallenge(kv: KVNamespace, challengeId: string): Promise<void> {
	try {
		await kv.delete(`challenge:${challengeId}`);
	} catch {
		// Ignore deletion errors
	}
}

// ==================== WebAuthn Registration ====================

/**
 * Generate registration options for navigator.credentials.create()
 *
 * Creates a PublicKeyCredentialCreationOptions object that the client
 * will use to register a new passkey.
 *
 * @param userId - User identifier
 * @param username - Username for display
 * @param rpId - Relying Party ID (domain)
 * @returns Options for credential creation
 */
export function generateRegistrationOptions(
	userId: string,
	username: string,
	rpId: string,
): PublicKeyCredentialCreationOptions {
	const challenge = generateChallenge();

	return {
		challenge,
		rp: {
			name: 'CFr2 WebDAV',
			id: rpId,
		},
		user: {
			id: TEXT_ENCODER.encode(userId),
			name: username,
			displayName: username,
		},
		pubKeyCredParams: [
			{ type: 'public-key', alg: -7 }, // ES256 (ECDSA with SHA-256)
			{ type: 'public-key', alg: -257 }, // RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
		],
		timeout: 60000, // 60 seconds
		attestation: 'none', // No attestation required
		authenticatorSelection: {
			authenticatorAttachment: 'platform', // Prefer platform authenticators
			requireResidentKey: false,
			userVerification: 'preferred',
		},
	};
}

/**
 * Verify registration response from authenticator
 *
 * Validates attestation object and extracts credential data:
 * - Verifies clientDataJSON (type, challenge, origin)
 * - Parses authenticatorData
 * - Extracts credential ID and public key
 * - Validates RP ID hash
 *
 * @param credential - PublicKeyCredential from navigator.credentials.create()
 * @param expectedChallenge - Challenge that was sent to client
 * @param rpId - Expected Relying Party ID
 * @param expectedOrigin - Expected origin (optional, for strict validation)
 * @returns Credential data for storage
 * @throws Error if validation fails
 */
export async function verifyRegistrationResponse(
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	credential: any,
	expectedChallenge: Uint8Array,
	rpId: string,
	expectedOrigin?: string,
): Promise<{ credentialId: string; publicKey: string; counter: number }> {
	// Validate credential structure
	if (!credential?.response?.attestationObject || !credential?.response?.clientDataJSON) {
		throw new Error('Malformed registration response: missing attestationObject or clientDataJSON');
	}

	// Step 1: Parse and validate clientDataJSON
	const clientData = parseClientDataJSON(credential.response.clientDataJSON);
	if (clientData.type !== 'webauthn.create') {
		throw new Error(`Invalid clientData type: expected "webauthn.create", got "${clientData.type}"`);
	}
	if (!challengeEquals(clientData.challenge, expectedChallenge)) {
		throw new Error('Challenge mismatch');
	}
	if (expectedOrigin && clientData.origin !== expectedOrigin) {
		throw new Error(`Origin mismatch: expected "${expectedOrigin}", got "${clientData.origin}"`);
	}

	// Step 2: Parse attestationObject (CBOR encoded)
	const attestationObject = decodeCbor(new Uint8Array(credential.response.attestationObject));
	const authDataBytes: Uint8Array = attestationObject.authData;
	if (!authDataBytes) {
		throw new Error('Missing authData in attestationObject');
	}

	// Step 3: Parse authenticatorData
	const authenticatorData = parseAuthenticatorData(authDataBytes.buffer as ArrayBuffer);
	await assertRpIdHash(authenticatorData.rpIdHash, rpId);

	if (!authenticatorData.flags.userPresent) {
		throw new Error('User not present during registration');
	}

	if (!authenticatorData.attestedCredential) {
		throw new Error('Missing attested credential data');
	}

	const { credentialId, credentialPublicKey } = authenticatorData.attestedCredential;

	// Step 4: Validate public key can be imported
	await importCosePublicKey(credentialPublicKey);

	return {
		credentialId: base64urlEncode(credentialId),
		publicKey: base64urlEncode(credentialPublicKey),
		counter: authenticatorData.signCount,
	};
}

// ==================== WebAuthn Authentication ====================

/**
 * Generate authentication options for navigator.credentials.get()
 *
 * Creates a PublicKeyCredentialRequestOptions object that the client
 * will use to authenticate with an existing passkey.
 *
 * @param userId - User identifier (unused but kept for consistency)
 * @param credentials - List of user's registered passkeys
 * @param rpId - Relying Party ID (domain)
 * @returns Options for credential request
 */
export function generateAuthenticationOptions(
	userId: string,
	credentials: PasskeyCredential[],
	rpId: string,
): PublicKeyCredentialRequestOptions {
	const challenge = generateChallenge();

	return {
		challenge,
		timeout: 60000,
		rpId,
		allowCredentials: credentials.map((cred) => ({
			type: 'public-key',
			id: base64urlDecode(cred.credentialId),
		})),
		userVerification: 'preferred',
	};
}

/**
 * Verify authentication response from authenticator
 *
 * Validates assertion and authenticator signature:
 * - Verifies clientDataJSON (type, challenge, origin)
 * - Parses authenticatorData
 * - Validates RP ID hash and flags
 * - Verifies signature using stored public key
 * - Checks counter increment (replay protection)
 *
 * @param credential - PublicKeyCredential from navigator.credentials.get()
 * @param expectedChallenge - Challenge that was sent to client
 * @param storedCredential - Stored credential data
 * @param rpId - Expected Relying Party ID
 * @param expectedOrigin - Expected origin (optional)
 * @returns Verification result with new counter
 * @throws Error if validation fails
 */
export async function verifyAuthenticationResponse(
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	credential: any,
	expectedChallenge: Uint8Array,
	storedCredential: PasskeyCredential,
	rpId: string,
	expectedOrigin?: string,
): Promise<{ verified: boolean; newCounter: number }> {
	// Validate credential structure
	if (
		!credential?.response?.authenticatorData ||
		!credential?.response?.clientDataJSON ||
		!credential?.response?.signature
	) {
		throw new Error('Malformed authentication response');
	}

	// Step 1: Parse and validate clientDataJSON
	const clientData = parseClientDataJSON(credential.response.clientDataJSON);
	if (clientData.type !== 'webauthn.get') {
		throw new Error(`Invalid clientData type: expected "webauthn.get", got "${clientData.type}"`);
	}
	if (!challengeEquals(clientData.challenge, expectedChallenge)) {
		throw new Error('Challenge mismatch');
	}
	if (expectedOrigin && clientData.origin !== expectedOrigin) {
		throw new Error(`Origin mismatch: expected "${expectedOrigin}", got "${clientData.origin}"`);
	}

	// Step 2: Parse authenticatorData
	const authDataBytes = new Uint8Array(credential.response.authenticatorData);
	const authenticatorData = parseAuthenticatorData(authDataBytes.buffer);
	await assertRpIdHash(authenticatorData.rpIdHash, rpId);

	if (!authenticatorData.flags.userPresent) {
		throw new Error('User not present during authentication');
	}

	// Step 3: Verify signature
	// Signature is over: authenticatorData || SHA-256(clientDataJSON)
	const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', credential.response.clientDataJSON));
	const signedData = concatUint8(authDataBytes, clientDataHash);
	const signature = new Uint8Array(credential.response.signature);

	const publicKeyBytes = base64urlDecode(storedCredential.publicKey);
	const cryptoKey = await importCosePublicKey(publicKeyBytes);
	const algorithm = getVerifyAlgorithm(publicKeyBytes);

	const verified = await crypto.subtle.verify(algorithm, cryptoKey, signature, signedData);
	if (!verified) {
		throw new Error('Signature verification failed');
	}

	// Step 4: Verify counter increment (replay protection)
	const newCounter = authenticatorData.signCount;
	if (storedCredential.counter > 0 && newCounter <= storedCredential.counter) {
		throw new Error(`Counter did not increase: stored=${storedCredential.counter}, received=${newCounter}`);
	}

	return { verified: true, newCounter };
}

// ==================== Parsing Helpers ====================

/**
 * Parse clientDataJSON buffer
 */
function parseClientDataJSON(buffer: ArrayBuffer): { type: string; challenge: string; origin: string } {
	const json = TEXT_DECODER.decode(buffer);
	return JSON.parse(json);
}

/**
 * Compare client challenge (base64url) with expected challenge bytes
 */
function challengeEquals(clientChallengeB64: string, expected: Uint8Array): boolean {
	return clientChallengeB64 === base64urlEncode(expected);
}

/**
 * Verify RP ID hash matches expected RP ID
 */
async function assertRpIdHash(rpIdHash: Uint8Array, rpId: string): Promise<void> {
	const expected = new Uint8Array(await crypto.subtle.digest('SHA-256', TEXT_ENCODER.encode(rpId)));
	if (bufferToHex(expected.buffer as ArrayBuffer) !== bufferToHex(rpIdHash.buffer as ArrayBuffer)) {
		throw new Error('rpIdHash mismatch: authenticator data is for different RP');
	}
}

/**
 * Parse authenticatorData structure
 *
 * Structure:
 * - rpIdHash: 32 bytes (SHA-256 of RP ID)
 * - flags: 1 byte
 * - signCount: 4 bytes (big-endian uint32)
 * - [attestedCredentialData]: variable length (only if AT flag is set)
 * - [extensions]: variable length (only if ED flag is set)
 *
 * @param buffer - AuthenticatorData bytes
 * @returns Parsed data
 */
function parseAuthenticatorData(buffer: ArrayBuffer): {
	rpIdHash: Uint8Array;
	flags: {
		userPresent: boolean;
		userVerified: boolean;
		attestedCredentialData: boolean;
		extensionsIncluded: boolean;
		raw: number;
	};
	signCount: number;
	attestedCredential?: {
		credentialId: Uint8Array;
		credentialPublicKey: Uint8Array;
	};
} {
	const view = new DataView(buffer);
	let offset = 0;

	// Parse rpIdHash (32 bytes)
	const rpIdHash = new Uint8Array(buffer.slice(offset, offset + 32));
	offset += 32;

	// Parse flags (1 byte)
	const flagsByte = view.getUint8(offset);
	offset += 1;

	// Parse signCount (4 bytes, big-endian)
	const signCount = view.getUint32(offset, false);
	offset += 4;

	const flags = {
		userPresent: (flagsByte & 0x01) !== 0, // UP (bit 0)
		userVerified: (flagsByte & 0x04) !== 0, // UV (bit 2)
		attestedCredentialData: (flagsByte & 0x40) !== 0, // AT (bit 6)
		extensionsIncluded: (flagsByte & 0x80) !== 0, // ED (bit 7)
		raw: flagsByte,
	};

	let attestedCredential: { credentialId: Uint8Array; credentialPublicKey: Uint8Array } | undefined;

	// Parse attestedCredentialData if present (only in registration)
	if (flags.attestedCredentialData) {
		// AAGUID (16 bytes) - skip
		offset += 16;

		// Credential ID length (2 bytes, big-endian)
		const credIdLen = view.getUint16(offset, false);
		offset += 2;

		// Credential ID
		const credentialId = new Uint8Array(buffer.slice(offset, offset + credIdLen));
		offset += credIdLen;

		// Credential Public Key (CBOR encoded, rest of buffer)
		const credentialPublicKey = new Uint8Array(buffer.slice(offset));

		attestedCredential = { credentialId, credentialPublicKey };
	}

	return { rpIdHash, flags, signCount, attestedCredential };
}

// ==================== COSE Public Key Handling ====================

/**
 * Import COSE public key as CryptoKey
 *
 * Supports:
 * - ES256 (ECDSA P-256 with SHA-256)
 * - RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
 *
 * @param coseKeyBytes - COSE encoded public key
 * @returns CryptoKey for signature verification
 * @throws Error if key type is unsupported
 */
async function importCosePublicKey(coseKeyBytes: Uint8Array): Promise<CryptoKey> {
	const cose = decodeCbor(coseKeyBytes);

	// COSE key parameters:
	// 1: kty (key type)
	// 3: alg (algorithm)
	// -1: crv (curve) or n (RSA modulus)
	// -2: x (EC x-coordinate) or e (RSA exponent)
	// -3: y (EC y-coordinate)
	const kty = cose.get(1) ?? cose.kty;
	const alg = cose.get(3) ?? cose.alg;

	// EC2 (ECDSA P-256)
	if (kty === 2 || alg === -7) {
		const x = toUint8(cose.get(-2));
		const y = toUint8(cose.get(-3));
		if (!x || !y) {
			throw new Error('Invalid EC key: missing x or y coordinate');
		}

		const jwk = {
			kty: 'EC',
			crv: 'P-256',
			x: base64urlEncode(x),
			y: base64urlEncode(y),
			ext: true,
			key_ops: ['verify'],
			alg: 'ES256',
		};

		return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
	}

	// RSA (RSASSA-PKCS1-v1_5)
	if (kty === 3 || alg === -257) {
		const n = toUint8(cose.get(-1));
		const e = toUint8(cose.get(-2));
		if (!n || !e) {
			throw new Error('Invalid RSA key: missing modulus or exponent');
		}

		const jwk = {
			kty: 'RSA',
			n: base64urlEncode(n),
			e: base64urlEncode(e),
			ext: true,
			key_ops: ['verify'],
			alg: 'RS256',
		};

		return crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
	}

	throw new Error(`Unsupported COSE key type: kty=${kty}, alg=${alg}`);
}

/**
 * Get verification algorithm for COSE public key
 */
function getVerifyAlgorithm(coseKeyBytes: Uint8Array): AlgorithmIdentifier {
	const cose = decodeCbor(coseKeyBytes);
	const alg = cose.get(3) ?? cose.alg;

	if (alg === -7) {
		return { name: 'ECDSA', hash: 'SHA-256' };
	}
	if (alg === -257) {
		return { name: 'RSASSA-PKCS1-v1_5' };
	}

	// Default fallback
	return { name: 'RSASSA-PKCS1-v1_5' };
}

// ==================== CBOR Decoder ====================

/**
 * Minimal CBOR decoder for WebAuthn
 *
 * Supports major types needed for WebAuthn:
 * - Type 0: Unsigned integer
 * - Type 1: Negative integer
 * - Type 2: Byte string
 * - Type 3: Text string
 * - Type 4: Array
 * - Type 5: Map
 *
 * Does NOT support:
 * - Indefinite length
 * - Floating point
 * - Simple values beyond integers
 * - Complex structures
 *
 * @param data - CBOR encoded bytes
 * @returns Decoded value
 * @throws Error if unsupported CBOR structure
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function decodeCbor(data: Uint8Array): any {
	let offset = 0;

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const read = (): any => {
		const byte = data[offset++];
		const major = byte >> 5;
		let len = byte & 0x1f;

		const readLength = (l: number): number => {
			if (l < 24) {
				return l;
			}
			if (l === 24) {
				return data[offset++];
			}
			if (l === 25) {
				const v = (data[offset] << 8) | data[offset + 1];
				offset += 2;
				return v;
			}
			if (l === 26) {
				const v = (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
				offset += 4;
				return v >>> 0;
			}
			throw new Error('CBOR length too large (64-bit not supported)');
		};

		const n = readLength(len);

		// Major type 0: Unsigned integer
		if (major === 0) {
			return n;
		}

		// Major type 1: Negative integer
		if (major === 1) {
			return -1 - n;
		}

		// Major type 2: Byte string
		if (major === 2) {
			const buf = data.slice(offset, offset + n);
			offset += n;
			return buf;
		}

		// Major type 3: Text string
		if (major === 3) {
			const buf = data.slice(offset, offset + n);
			offset += n;
			return TEXT_DECODER.decode(buf);
		}

		// Major type 4: Array
		if (major === 4) {
			const arr = [];
			for (let i = 0; i < n; i++) {
				arr.push(read());
			}
			return arr;
		}

		// Major type 5: Map
		if (major === 5) {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const map = new Map<any, any>();
			for (let i = 0; i < n; i++) {
				const k = read();
				const v = read();
				map.set(k, v);
			}
			return map;
		}

		throw new Error(`Unsupported CBOR major type: ${major}`);
	};

	return read();
}

// ==================== Helper Functions ====================

/**
 * Convert value to Uint8Array if possible
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function toUint8(v: any): Uint8Array | null {
	if (!v) {
		return null;
	}
	if (v instanceof Uint8Array) {
		return v;
	}
	if (Array.isArray(v)) {
		return new Uint8Array(v);
	}
	return null;
}
