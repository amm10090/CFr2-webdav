/**
 * Password hashing utilities using PBKDF2
 *
 * This module provides secure password hashing and verification using the
 * Web Crypto API's PBKDF2 implementation. Passwords are hashed with a random
 * salt and stored in a versioned format for future upgrade paths.
 *
 * Format: v1:iterations:base64(salt):base64(hash)
 * Example: v1:100000:MTIzNDU2Nzg5MDEyMzQ1Ng==:abcdef...
 */

const TEXT_ENCODER = new TextEncoder();
export const DEFAULT_PBKDF2_ITERATIONS = 100_000;
const MIN_PBKDF2_ITERATIONS = 100_000; // Minimum for security
const MAX_PBKDF2_ITERATIONS = 1_000_000; // Maximum to prevent DoS
const SALT_LENGTH = 16; // 128 bits
const HASH_LENGTH = 32; // 256 bits

/**
 * Converts a Uint8Array to a base64 string
 */
function toBase64(buffer: Uint8Array): string {
	return btoa(String.fromCharCode(...buffer));
}

/**
 * Converts a base64 string to a Uint8Array
 * @throws {Error} If base64 string is invalid
 */
function fromBase64(base64: string): Uint8Array {
	try {
		return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
	} catch {
		throw new Error('Invalid base64 encoding');
	}
}

/**
 * Hashes a password using PBKDF2 with SHA-256
 *
 * @param password - The plaintext password to hash
 * @param iterations - Number of PBKDF2 iterations (default: 100,000)
 * @returns A versioned hash string in format: v1:iterations:salt:hash
 *
 * @example
 * const hashed = await hashPassword("mySecurePassword123");
 * // Returns: "v1:100000:MTIzNDU2Nzg5MDEyMzQ1Ng==:abcdef..."
 */
export async function hashPassword(
	password: string,
	iterations: number = DEFAULT_PBKDF2_ITERATIONS
): Promise<string> {
	// Validate iterations to prevent DoS and ensure security
	if (iterations < MIN_PBKDF2_ITERATIONS) {
		throw new Error(`PBKDF2 iterations must be at least ${MIN_PBKDF2_ITERATIONS} for security`);
	}
	if (iterations > MAX_PBKDF2_ITERATIONS) {
		throw new Error(`PBKDF2 iterations cannot exceed ${MAX_PBKDF2_ITERATIONS} to prevent DoS`);
	}

	// Generate a cryptographically secure random salt
	const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));

	// Import the password as a key
	const passwordKey = await crypto.subtle.importKey(
		'raw',
		TEXT_ENCODER.encode(password),
		'PBKDF2',
		false,
		['deriveBits']
	);

	// Derive the hash using PBKDF2
	const derivedBits = await crypto.subtle.deriveBits(
		{
			name: 'PBKDF2',
			salt: salt,
			iterations: iterations,
			hash: 'SHA-256',
		},
		passwordKey,
		HASH_LENGTH * 8 // bits
	);

	const hashArray = new Uint8Array(derivedBits);

	// Return versioned format for future upgrade paths
	return `v1:${iterations}:${toBase64(salt)}:${toBase64(hashArray)}`;
}

/**
 * Verifies a password against a stored hash using constant-time comparison
 *
 * @param password - The plaintext password to verify
 * @param storedHash - The stored hash string (format: v1:iterations:salt:hash)
 * @returns True if the password matches, false otherwise
 *
 * @example
 * const isValid = await verifyPassword(
 *   "mySecurePassword123",
 *   "v1:100000:MTIzNDU2Nzg5MDEyMzQ1Ng==:abcdef..."
 * );
 */
export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
	// Parse the stored hash
	const parts = storedHash.split(':');
	if (parts.length !== 4) {
		throw new Error('Invalid hash format');
	}

	const [version, iterStr, saltB64, hashB64] = parts;

	// Version check for future upgrade paths
	if (version !== 'v1') {
		throw new Error(`Unsupported hash version: ${version}`);
	}

	const iterations = parseInt(iterStr, 10);
	if (isNaN(iterations) || iterations <= 0) {
		throw new Error('Invalid iteration count');
	}
	if (iterations < MIN_PBKDF2_ITERATIONS || iterations > MAX_PBKDF2_ITERATIONS) {
		throw new Error(`Iteration count out of valid range (${MIN_PBKDF2_ITERATIONS}-${MAX_PBKDF2_ITERATIONS})`);
	}

	const salt = fromBase64(saltB64);
	const storedHashBytes = fromBase64(hashB64);

	// Derive a hash from the provided password using the stored salt
	const passwordKey = await crypto.subtle.importKey(
		'raw',
		TEXT_ENCODER.encode(password),
		'PBKDF2',
		false,
		['deriveBits']
	);

	const derivedBits = await crypto.subtle.deriveBits(
		{
			name: 'PBKDF2',
			salt: salt,
			iterations: iterations,
			hash: 'SHA-256',
		},
		passwordKey,
		storedHashBytes.length * 8
	);

	const candidateHash = new Uint8Array(derivedBits);

	// Constant-time comparison to prevent timing attacks
	return timingSafeEqual(candidateHash, storedHashBytes);
}

/**
 * Compares two Uint8Arrays in constant time to prevent timing attacks
 *
 * @param a - First byte array
 * @param b - Second byte array
 * @returns True if arrays are equal, false otherwise
 */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) {
		return false;
	}

	let result = 0;
	for (let i = 0; i < a.length; i++) {
		result |= a[i] ^ b[i];
	}

	return result === 0;
}

/**
 * Generates a password hash suitable for storage in environment variables
 * This is a helper function for initial setup
 *
 * @param password - The plaintext password to hash
 * @returns A promise that resolves to the hash string
 *
 * @example
 * // Usage in a setup script:
 * const hash = await hashPassword("admin123");
 * console.log("Add this to your wrangler.toml:");
 * console.log(`PASSWORD_HASH = "${hash}"`);
 */
export async function generatePasswordHashForEnv(password: string): Promise<string> {
	return hashPassword(password);
}
