// 文件名：src/utils/recoveryCodes.ts
/**
 * Recovery Codes for Two-Factor Authentication
 *
 * Provides backup authentication method when TOTP device is unavailable.
 * Recovery codes are one-time use and should be securely stored by the user.
 */

import { hashPassword, verifyPassword } from './crypto';

/**
 * Generate cryptographically secure recovery codes
 *
 * Creates one-time use backup codes for 2FA recovery. Each code is 8 hexadecimal
 * characters (32 bits of entropy). Users should store these securely offline.
 *
 * @param count - Number of recovery codes to generate (default: 10)
 * @returns Array of recovery codes in format XXXX-XXXX
 *
 * @example
 * const codes = generateRecoveryCodes(10);
 * // Returns: ["A3B2-C5D7", "F1E8-9A42", ...]
 */
export function generateRecoveryCodes(count: number = 10): string[] {
	if (count < 1 || count > 100) {
		throw new Error('Recovery code count must be between 1 and 100');
	}

	const codes: string[] = [];

	for (let i = 0; i < count; i++) {
		// Generate 4 random bytes (8 hex characters)
		const randomBytes = crypto.getRandomValues(new Uint8Array(4));
		const hexString = Array.from(randomBytes)
			.map((b) => b.toString(16).padStart(2, '0'))
			.join('')
			.toUpperCase();

		// Format as XXXX-XXXX for readability
		const formatted = `${hexString.slice(0, 4)}-${hexString.slice(4)}`;
		codes.push(formatted);
	}

	return codes;
}

/**
 * Hash a recovery code for secure storage
 *
 * Uses PBKDF2 with same parameters as password hashing to securely
 * store recovery codes. This prevents recovery code theft if the database
 * is compromised.
 *
 * @param code - Recovery code to hash (with or without hyphen)
 * @returns Hashed recovery code in v1:iterations:salt:hash format
 *
 * @example
 * const hash = await hashRecoveryCode("A3B2-C5D7");
 */
export async function hashRecoveryCode(code: string): Promise<string> {
	// Normalize: remove hyphen and convert to uppercase
	const normalized = code.replace(/-/g, '').toUpperCase();

	// Validate format
	if (!/^[0-9A-F]{8}$/.test(normalized)) {
		throw new Error('Invalid recovery code format');
	}

	// Use same hashing function as passwords for consistency
	return await hashPassword(normalized);
}

/**
 * Verify a recovery code against its hash
 *
 * @param code - Recovery code to verify (with or without hyphen)
 * @param hash - Stored hash in v1:iterations:salt:hash format
 * @returns True if code matches hash, false otherwise
 *
 * @example
 * const isValid = await verifyRecoveryCode("A3B2-C5D7", storedHash);
 */
export async function verifyRecoveryCode(code: string, hash: string): Promise<boolean> {
	try {
		// Normalize code
		const normalized = code.replace(/-/g, '').toUpperCase();

		// Validate format
		if (!/^[0-9A-F]{8}$/.test(normalized)) {
			return false;
		}

		// Use same verification function as passwords
		return await verifyPassword(normalized, hash);
	} catch {
		return false;
	}
}

/**
 * Format recovery codes for display
 *
 * Groups recovery codes for better readability and printability.
 * Useful for showing codes to user after generation.
 *
 * @param codes - Array of recovery codes
 * @returns Formatted string with numbered codes
 *
 * @example
 * const display = formatRecoveryCodesForDisplay(codes);
 * // Returns:
 * // 1. A3B2-C5D7
 * // 2. F1E8-9A42
 * // ...
 */
export function formatRecoveryCodesForDisplay(codes: string[]): string {
	return codes.map((code, index) => `${index + 1}. ${code}`).join('\n');
}

/**
 * Validate recovery code format
 *
 * Checks if a string is a valid recovery code format without verifying
 * against a hash. Useful for client-side validation.
 *
 * @param code - Code to validate
 * @returns True if format is valid
 *
 * @example
 * isValidRecoveryCodeFormat("A3B2-C5D7"); // true
 * isValidRecoveryCodeFormat("invalid"); // false
 */
export function isValidRecoveryCodeFormat(code: string): boolean {
	if (!code) {
		return false;
	}

	// Accept with or without hyphen
	const normalized = code.replace(/-/g, '').toUpperCase();
	return /^[0-9A-F]{8}$/.test(normalized);
}
