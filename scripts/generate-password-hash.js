#!/usr/bin/env node

/**
 * Generate password hash for CFr2-webdav
 *
 * Usage: node scripts/generate-password-hash.js <password>
 */

async function generateHash(password) {
	const encoder = new TextEncoder();
	const data = encoder.encode(password);
	const salt = crypto.getRandomValues(new Uint8Array(16));

	const key = await crypto.subtle.importKey('raw', data, 'PBKDF2', false, ['deriveBits']);

	const derivedBits = await crypto.subtle.deriveBits(
		{
			name: 'PBKDF2',
			salt: salt,
			iterations: 100000,
			hash: 'SHA-256',
		},
		key,
		256,
	);

	const hashArray = new Uint8Array(derivedBits);
	const toBase64 = (arr) => Buffer.from(arr).toString('base64');

	return `v1:100000:${toBase64(salt)}:${toBase64(hashArray)}`;
}

// Get password from command line argument
const password = process.argv[2];

if (!password) {
	console.error('Error: Password argument required');
	console.error('Usage: node scripts/generate-password-hash.js <password>');
	process.exit(1);
}

if (password.length < 8) {
	console.warn('Warning: Password is less than 8 characters. Consider using a stronger password.');
}

console.log('Generating password hash...\n');

generateHash(password)
	.then((hash) => {
		console.log('Password Hash (add this to wrangler.toml):');
		console.log('PASSWORD_HASH = "' + hash + '"');
		console.log('\nFormat: v1:iterations:salt:hash');
		console.log('Iterations: 100,000');
		console.log('Algorithm: PBKDF2-SHA256\n');
	})
	.catch((err) => {
		console.error('Error generating hash:', err.message);
		process.exit(1);
	});
