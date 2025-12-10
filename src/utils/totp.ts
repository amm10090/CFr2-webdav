// 文件名：src/utils/totp.ts
/**
 * TOTP (Time-based One-Time Password) Implementation
 *
 * Implements RFC 6238 TOTP algorithm for two-factor authentication.
 * Uses 30-second time windows with ±1 window tolerance for clock skew.
 */

/**
 * Base32 alphabet (RFC 4648)
 */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * TOTP configuration constants
 */
const TOTP_WINDOW_SECONDS = 30;
const TOTP_DIGITS = 6;
const TOTP_ALGORITHM = 'SHA-1';

/**
 * Generate a random TOTP secret
 *
 * Creates a cryptographically secure 20-byte (160-bit) secret key
 * and encodes it in Base32 format for compatibility with authenticator apps.
 *
 * @returns Base32-encoded secret key
 *
 * @example
 * const secret = await generateTOTPSecret();
 * // Returns: "JBSWY3DPEHPK3PXP"
 */
export async function generateTOTPSecret(): Promise<string> {
	const secret = crypto.getRandomValues(new Uint8Array(20));
	return base32Encode(secret);
}

/**
 * Verify a TOTP code against a secret
 *
 * Checks the provided code against the current time window and ±1 adjacent windows
 * to account for clock skew and user input time.
 *
 * @param secret - Base32-encoded TOTP secret
 * @param code - 6-digit TOTP code to verify
 * @returns True if code is valid, false otherwise
 *
 * @example
 * const isValid = await verifyTOTP(secret, '123456');
 */
export async function verifyTOTP(secret: string, code: string): Promise<boolean> {
	if (!code || code.length !== TOTP_DIGITS) {
		return false;
	}

	// Validate code is numeric
	if (!/^\d{6}$/.test(code)) {
		return false;
	}

	const currentWindow = Math.floor(Date.now() / 1000 / TOTP_WINDOW_SECONDS);

	// Check current window and ±1 window for clock skew tolerance
	for (const window of [currentWindow - 1, currentWindow, currentWindow + 1]) {
		try {
			const expectedCode = await generateTOTPCode(secret, window);
			if (code === expectedCode) {
				return true;
			}
		} catch {
			// Invalid secret or generation error
			return false;
		}
	}

	return false;
}

/**
 * Generate TOTP code for a specific time window
 *
 * @param secret - Base32-encoded TOTP secret
 * @param timeWindow - Time window counter (defaults to current time)
 * @returns 6-digit TOTP code
 */
export async function generateTOTPCode(secret: string, timeWindow?: number): Promise<string> {
	const window = timeWindow ?? Math.floor(Date.now() / 1000 / TOTP_WINDOW_SECONDS);

	// Decode Base32 secret to bytes
	const secretBytes = base32Decode(secret);

	// Convert time window to 8-byte big-endian buffer
	const timeBuffer = new ArrayBuffer(8);
	const timeView = new DataView(timeBuffer);
	timeView.setUint32(4, window, false); // Big-endian

	// Import secret as HMAC key
	const key = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: TOTP_ALGORITHM }, false, [
		'sign',
	]);

	// Generate HMAC-SHA1
	const signature = await crypto.subtle.sign('HMAC', key, timeBuffer);
	const hmac = new Uint8Array(signature);

	// Dynamic truncation (RFC 4226)
	const offset = hmac[hmac.length - 1] & 0x0f;
	const code =
		((hmac[offset] & 0x7f) << 24) |
		((hmac[offset + 1] & 0xff) << 16) |
		((hmac[offset + 2] & 0xff) << 8) |
		(hmac[offset + 3] & 0xff);

	// Generate 6-digit code
	const otp = code % 10 ** TOTP_DIGITS;
	return otp.toString().padStart(TOTP_DIGITS, '0');
}

/**
 * Generate otpauth:// URI for QR code generation
 *
 * Creates a URI that can be encoded in a QR code for easy setup
 * in authenticator apps like Google Authenticator, Authy, etc.
 *
 * @param secret - Base32-encoded TOTP secret
 * @param accountName - Account identifier (usually username)
 * @param issuer - Service name (defaults to "CFr2-WebDAV")
 * @returns otpauth:// URI string
 *
 * @example
 * const uri = generateTOTPUri(secret, "user@example.com", "MyService");
 * // Returns: "otpauth://totp/MyService:user@example.com?secret=...&issuer=MyService"
 */
export function generateTOTPUri(secret: string, accountName: string, issuer: string = 'CFr2-WebDAV'): string {
	const params = new URLSearchParams({
		secret: secret,
		issuer: issuer,
		algorithm: TOTP_ALGORITHM,
		digits: TOTP_DIGITS.toString(),
		period: TOTP_WINDOW_SECONDS.toString(),
	});

	return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}?${params.toString()}`;
}

/**
 * Encode bytes to Base32 (RFC 4648)
 *
 * @param data - Byte array to encode
 * @returns Base32-encoded string
 */
export function base32Encode(data: Uint8Array): string {
	let result = '';
	let bits = 0;
	let value = 0;

	for (let i = 0; i < data.length; i++) {
		value = (value << 8) | data[i];
		bits += 8;

		while (bits >= 5) {
			result += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
			bits -= 5;
		}
	}

	if (bits > 0) {
		result += BASE32_ALPHABET[(value << (5 - bits)) & 31];
	}

	// Add padding
	while (result.length % 8 !== 0) {
		result += '=';
	}

	return result;
}

/**
 * Decode Base32 string to bytes (RFC 4648)
 *
 * @param encoded - Base32-encoded string
 * @returns Decoded byte array
 * @throws Error if input contains invalid Base32 characters
 */
export function base32Decode(encoded: string): Uint8Array {
	// Remove padding and convert to uppercase
	const clean = encoded.replace(/=+$/, '').toUpperCase();

	// Validate Base32 characters
	for (const char of clean) {
		if (!BASE32_ALPHABET.includes(char)) {
			throw new Error(`Invalid Base32 character: ${char}`);
		}
	}

	const result: number[] = [];
	let bits = 0;
	let value = 0;

	for (let i = 0; i < clean.length; i++) {
		value = (value << 5) | BASE32_ALPHABET.indexOf(clean[i]);
		bits += 5;

		if (bits >= 8) {
			result.push((value >>> (bits - 8)) & 255);
			bits -= 8;
		}
	}

	return new Uint8Array(result);
}
