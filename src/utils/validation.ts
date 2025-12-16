/**
 * Input validation utilities for file operations
 *
 * This module provides comprehensive validation for file uploads and operations:
 * - File name validation (whitelist + dangerous character checks)
 * - File size validation (single file and total quota)
 * - Content-Type validation (blacklist for dangerous types)
 * - Storage quota tracking and enforcement
 *
 * Security considerations:
 * - Prevents path traversal attacks
 * - Blocks dangerous file types
 * - Enforces storage quotas
 * - Validates all user input
 */

// File size limits
export const FILE_SIZE_LIMIT = 100 * 1024 * 1024; // 100 MB
export const TOTAL_STORAGE_LIMIT = 10 * 1024 * 1024 * 1024; // 10 GB

/**
 * Allowed file extensions (whitelist approach for security)
 *
 * Only files with these extensions can be uploaded.
 * Executable types and sensitive configuration files are excluded.
 */
const ALLOWED_EXTENSIONS = new Set([
	// Documents
	'txt',
	'md',
	'pdf',
	'doc',
	'docx',
	'xls',
	'xlsx',
	'ppt',
	'pptx',
	'odt',
	'ods',
	'odp',
	'rtf',

	// Images
	'jpg',
	'jpeg',
	'png',
	'gif',
	'svg',
	'webp',
	'bmp',
	'ico',
	'tiff',
	'tif',
	'heic',
	'heif',
	'avif',

	// Audio
	'mp3',
	'wav',
	'flac',
	'aac',
	'ogg',
	'opus',
	'm4a',

	// Video
	'mp4',
	'webm',
	'mkv',
	'avi',
	'mov',
	'flv',
	'm4v',

	// Archives
	'zip',
	'rar',
	'7z',
	'tar',
	'gz',

	// Data and config (non-executable)
	'json',
	'xml',
	'yml',
	'yaml',
	'toml',
	'csv',
	'tsv',
	'sql',

	// Fonts
	'ttf',
	'otf',
	'woff',
	'woff2',
]);

/**
 * Dangerous MIME types that should never be allowed (blacklist)
 *
 * These types can execute code or pose security risks.
 */
const DANGEROUS_MIME_TYPES = new Set([
	// Executable files
	'application/x-msdownload', // .exe
	'application/x-executable',
	'application/x-sharedlib',
	'application/x-msdos-program',
	'application/x-mach-binary',
	'application/x-dosexec',

	// Script types (can execute in browser or server)
	'application/x-sh',
	'application/x-bash',
	'text/x-shellscript',
	'application/x-perl',
	'application/x-python',
	'application/x-ruby',
	'application/x-php',
	'application/javascript',
	'application/x-javascript',
	'text/javascript',
	'text/html',
	'application/xhtml+xml',

	// Windows specific
	'application/x-ms-dos-executable',
	'application/vnd.microsoft.portable-executable',
	'application/x-bat',
	'application/x-cmd',

	// Java and other bytecode
	'application/java-archive',
	'application/x-java-applet',
]);

/**
 * Validate a file name for security and compatibility
 *
 * Checks for:
 * - Empty names
 * - Excessive length
 * - Dangerous characters (null bytes, path separators, etc.)
 * - Disallowed extensions
 * - Hidden files (configurable)
 *
 * @param filename - File name to validate
 * @param allowHidden - Whether to allow hidden files (starting with .)
 * @throws {Error} If validation fails with descriptive message
 *
 * @example
 * try {
 *   validateFileName('document.pdf');
 *   // File name is valid
 * } catch (err) {
 *   console.error('Invalid file name:', err.message);
 * }
 */
export function validateFileName(filename: string, allowHidden = false): void {
	// Check for empty name
	if (!filename || filename.trim().length === 0) {
		throw new Error('File name cannot be empty');
	}

	// Check length
	if (filename.length > 255) {
		throw new Error('File name too long (maximum 255 characters)');
	}

	// Check for dangerous characters
	// \x00-\x1f: Control characters (including null byte)
	// \x7f: DEL character
	// <>:"|?*: Windows forbidden characters
	// \/: Path separators
	const dangerousChars = /[\x00-\x1f\x7f<>:"|?*\\/]/;
	if (dangerousChars.test(filename)) {
		throw new Error('File name contains invalid characters');
	}

	// Check for path traversal attempts
	if (filename.includes('..')) {
		throw new Error('File name cannot contain ".."');
	}

	// Check for hidden files (optional)
	if (!allowHidden && filename.startsWith('.')) {
		throw new Error('Hidden files are not allowed');
	}

	// Check extension
	const parts = filename.split('.');
	if (parts.length < 2) {
		throw new Error('File must have an extension');
	}

	const ext = parts[parts.length - 1].toLowerCase();
	if (!ALLOWED_EXTENSIONS.has(ext)) {
		throw new Error(`File extension '.${ext}' is not allowed`);
	}

	// Additional check: prevent double extensions (e.g., file.pdf.exe, document.txt.sh)
	// Only the final extension matters; any other dots should be part of the base name
	if (parts.length > 2) {
		// Check if any part before the final extension looks like a file extension
		// This prevents files like "malware.exe.txt" or "script.php.jpg"
		for (let i = 1; i < parts.length - 1; i++) {
			const part = parts[i].toLowerCase();
			// Check if this looks like a common executable extension (3-4 chars)
			if (part.length >= 2 && part.length <= 4 && /^[a-z0-9]+$/.test(part)) {
				// List of dangerous extensions that should never appear before the real extension
				const suspiciousExts = new Set([
					'exe',
					'bat',
					'cmd',
					'com',
					'scr',
					'vbs',
					'vbe',
					'js',
					'jse',
					'ws',
					'wsf',
					'wsh',
					'msi',
					'jar',
					'app',
					'deb',
					'rpm',
					'dmg',
					'pkg',
					'sh',
					'bash',
					'ps1',
					'php',
					'py',
					'rb',
					'pl',
				]);
				if (suspiciousExts.has(part)) {
					throw new Error(`Suspicious double extension detected: '${part}' should not appear before final extension`);
				}
			}
		}
	}
}

/**
 * Validate a directory name for security
 *
 * Similar to file validation but allows no extension.
 *
 * @param dirname - Directory name to validate
 * @throws {Error} If validation fails
 */
export function validateDirectoryName(dirname: string): void {
	// Check for empty name
	if (!dirname || dirname.trim().length === 0) {
		throw new Error('Directory name cannot be empty');
	}

	// Check length
	if (dirname.length > 255) {
		throw new Error('Directory name too long (maximum 255 characters)');
	}

	// Check for dangerous characters
	const dangerousChars = /[\x00-\x1f\x7f<>:"|?*\\/]/;
	if (dangerousChars.test(dirname)) {
		throw new Error('Directory name contains invalid characters');
	}

	// Check for path traversal
	if (dirname.includes('..')) {
		throw new Error('Directory name cannot contain ".."');
	}

	// Disallow hidden directories
	if (dirname.startsWith('.')) {
		throw new Error('Hidden directories are not allowed');
	}

	// Disallow reserved names (Windows compatibility)
	const reservedNames = new Set(['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'LPT1']);
	if (reservedNames.has(dirname.toUpperCase())) {
		throw new Error('Directory name is reserved');
	}
}

/**
 * Validate file size against the maximum allowed
 *
 * @param size - File size in bytes
 * @param maxSize - Maximum allowed size (default: FILE_SIZE_LIMIT)
 * @throws {Error} If size exceeds limit
 *
 * @example
 * validateFileSize(file.size);
 */
export function validateFileSize(size: number, maxSize: number = FILE_SIZE_LIMIT): void {
	if (size <= 0) {
		throw new Error('File size must be greater than 0');
	}

	if (size > maxSize) {
		const maxSizeMB = Math.floor(maxSize / 1024 / 1024);
		throw new Error(`File size exceeds limit of ${maxSizeMB} MB`);
	}
}

/**
 * Validate Content-Type header against dangerous types
 *
 * Uses a blacklist approach to block known dangerous MIME types.
 *
 * @param contentType - Content-Type header value
 * @throws {Error} If content type is dangerous
 *
 * @example
 * validateContentType(request.headers.get('Content-Type'));
 */
export function validateContentType(contentType: string | null): void {
	if (!contentType) {
		// Allow missing Content-Type (will be inferred by browser)
		return;
	}

	// Extract MIME type (ignore parameters like charset)
	const mimeType = contentType.split(';')[0].trim().toLowerCase();

	if (DANGEROUS_MIME_TYPES.has(mimeType)) {
		throw new Error(`Content-Type '${mimeType}' is not allowed for security reasons`);
	}
}

/**
 * Storage quota state stored in KV
 */
interface StorageQuotaState {
	totalBytes: number; // Total bytes used
	lastUpdated: number; // Last update timestamp (Unix ms)
	fileCount: number; // Number of files stored
}

/**
 * Check if uploading a file would exceed storage quota
 *
 * This function queries the current storage usage from KV and verifies
 * that adding the new file would not exceed the configured quota.
 *
 * Note: R2 does not provide a native API to get bucket size, so we
 * track this ourselves in KV.
 *
 * @param kv - KV namespace for quota tracking
 * @param newFileSize - Size of file to be uploaded (bytes)
 * @param maxQuota - Maximum storage quota (default: TOTAL_STORAGE_LIMIT)
 * @returns Current usage and whether upload is allowed
 * @throws {Error} If quota would be exceeded
 *
 * @example
 * const quotaInfo = await checkStorageQuota(env.QUOTA_KV, file.size);
 * console.log(`Using ${quotaInfo.usedBytes} of ${quotaInfo.maxBytes} bytes`);
 */
export async function checkStorageQuota(
	kv: KVNamespace,
	newFileSize: number,
	maxQuota: number = TOTAL_STORAGE_LIMIT,
): Promise<{ usedBytes: number; maxBytes: number; availableBytes: number }> {
	const key = 'storage:quota';

	// Get current usage
	const stateJson = await kv.get(key);
	const state: StorageQuotaState = stateJson
		? JSON.parse(stateJson)
		: {
				totalBytes: 0,
				lastUpdated: Date.now(),
				fileCount: 0,
			};

	const usedBytes = state.totalBytes;
	const availableBytes = maxQuota - usedBytes;

	// Check if new file would exceed quota
	if (usedBytes + newFileSize > maxQuota) {
		const quotaGB = Math.floor(maxQuota / 1024 / 1024 / 1024);
		const usedGB = (usedBytes / 1024 / 1024 / 1024).toFixed(2);
		const neededMB = Math.ceil(newFileSize / 1024 / 1024);
		throw new Error(
			`Storage quota exceeded: using ${usedGB} GB of ${quotaGB} GB. ` + `Cannot upload ${neededMB} MB file.`,
		);
	}

	return {
		usedBytes,
		maxBytes: maxQuota,
		availableBytes,
	};
}

/**
 * Update storage quota after a file operation
 *
 * Call this after successfully uploading or deleting a file to update
 * the tracked storage usage.
 *
 * @param kv - KV namespace for quota tracking
 * @param deltaBytes - Change in storage (positive for upload, negative for delete)
 * @param deltaFiles - Change in file count (1 for upload, -1 for delete)
 *
 * @example
 * // After uploading a file
 * await updateStorageQuota(env.QUOTA_KV, file.size, 1);
 *
 * // After deleting a file
 * await updateStorageQuota(env.QUOTA_KV, -fileSize, -1);
 */
export async function updateStorageQuota(kv: KVNamespace, deltaBytes: number, deltaFiles: number): Promise<void> {
	const key = 'storage:quota';

	// Get current state
	const stateJson = await kv.get(key);
	const state: StorageQuotaState = stateJson
		? JSON.parse(stateJson)
		: {
				totalBytes: 0,
				lastUpdated: Date.now(),
				fileCount: 0,
			};

	// Update state
	const newState: StorageQuotaState = {
		totalBytes: Math.max(0, state.totalBytes + deltaBytes),
		lastUpdated: Date.now(),
		fileCount: Math.max(0, state.fileCount + deltaFiles),
	};

	// Save back to KV (no expiration, persistent tracking)
	await kv.put(key, JSON.stringify(newState));
}

/**
 * Get current storage quota information
 *
 * @param kv - KV namespace for quota tracking
 * @param maxQuota - Maximum storage quota (default: TOTAL_STORAGE_LIMIT)
 * @returns Current storage usage statistics
 *
 * @example
 * const info = await getStorageQuotaInfo(env.QUOTA_KV);
 * console.log(`Files: ${info.fileCount}, Used: ${info.usedBytes} bytes`);
 */
export async function getStorageQuotaInfo(
	kv: KVNamespace,
	maxQuota: number = TOTAL_STORAGE_LIMIT,
): Promise<{
	usedBytes: number;
	maxBytes: number;
	availableBytes: number;
	fileCount: number;
	percentUsed: number;
}> {
	const key = 'storage:quota';

	const stateJson = await kv.get(key);
	const state: StorageQuotaState = stateJson
		? JSON.parse(stateJson)
		: {
				totalBytes: 0,
				lastUpdated: Date.now(),
				fileCount: 0,
			};

	const usedBytes = state.totalBytes;
	const availableBytes = maxQuota - usedBytes;
	const percentUsed = (usedBytes / maxQuota) * 100;

	return {
		usedBytes,
		maxBytes: maxQuota,
		availableBytes,
		fileCount: state.fileCount,
		percentUsed,
	};
}
