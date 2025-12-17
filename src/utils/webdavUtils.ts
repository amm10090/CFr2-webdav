// 文件名：src/utils/webdavUtils.ts
import { R2Object } from '@cloudflare/workers-types';
import { WebDAVProps } from '../types';

/**
 * Validate a resource path for security
 *
 * Prevents:
 * - Path traversal attacks (../)
 * - Absolute paths (starting with /)
 * - Dangerous characters (null bytes, etc.)
 * - Excessively long paths
 *
 * @param path - Path to validate
 * @throws {Error} If path is invalid or dangerous
 */
function validatePath(path: string): void {
	// Empty path is allowed (represents root)
	if (!path || path.length === 0) {
		return;
	}

	// Check path length
	if (path.length > 1024) {
		throw new Error('Path too long (maximum 1024 characters)');
	}

	// Prohibit path traversal attempts
	if (path.includes('..')) {
		throw new Error('Path traversal not allowed');
	}

	// Prohibit absolute paths (should be relative)
	if (path.startsWith('/')) {
		throw new Error('Absolute paths not allowed');
	}

	// Prohibit dangerous characters
	// \x00-\x1f: Control characters (including null byte)
	// \x7f: DEL character
	// <>:"|?*: Windows forbidden characters that may cause issues
	const dangerousChars = /[\x00-\x1f\x7f<>:"|?*]/;
	if (dangerousChars.test(path)) {
		throw new Error('Path contains invalid characters');
	}

	// Validate each path segment
	const segments = path.split('/');
	for (const segment of segments) {
		// Skip empty segments (consecutive slashes)
		if (segment.length === 0) {
			continue;
		}

		// Prohibit . and .. as path segments
		if (segment === '.' || segment === '..') {
			throw new Error('Invalid path segment');
		}

		// Check segment length
		if (segment.length > 255) {
			throw new Error('Path segment too long (maximum 255 characters)');
		}
	}
}

export function make_resource_path(request: Request): string {
	const url = new URL(request.url);
	const normalized = url.pathname.replace(/\/+/g, '/'); // 合并重复斜杠，避免 "//file" 导致路径解析异常
	const sliced = normalized.slice(1); // 去掉开头的斜杠
	// 若 Worker 挂载在 /webdav 子路径，去掉该前缀以匹配 R2 的实际对象键
	const withoutPrefix = sliced.startsWith('webdav/')
		? sliced.slice('webdav/'.length)
		: sliced === 'webdav'
			? ''
			: sliced;

	// Decode URI component，捕获非法编码避免抛出 500
	let decoded: string;
	try {
		decoded = decodeURIComponent(withoutPrefix);
	} catch {
		throw new Error('Invalid path encoding');
	}

	// Validate path for security
	validatePath(decoded);

	return decoded;
}

export async function* listAll(bucket: R2Bucket, prefix: string) {
	const options = { prefix, delimiter: '/' };
	let result = await bucket.list(options);

	while (result.objects.length > 0) {
		for (const object of result.objects) {
			yield object;
		}

		if (result.truncated && result.cursor) {
			result = await bucket.list({ ...options, cursor: result.cursor });
		} else {
			break;
		}
	}
}

export function fromR2Object(object: R2Object | null): WebDAVProps {
	if (!object) {
		return {
			creationdate: new Date().toUTCString(),
			displayname: undefined,
			getcontentlanguage: undefined,
			getcontentlength: '0',
			getcontenttype: undefined,
			getetag: undefined,
			getlastmodified: new Date().toUTCString(),
			resourcetype: 'collection',
		};
	}
	return {
		creationdate: object.uploaded.toUTCString(),
		displayname: object.key.split('/').pop(),
		getcontentlanguage: object.httpMetadata?.contentLanguage,
		getcontentlength: object.size.toString(),
		getcontenttype: object.httpMetadata?.contentType,
		getetag: object.etag,
		getlastmodified: object.uploaded.toUTCString(),
		resourcetype: object.customMetadata?.resourcetype || '',
	};
}

export function generatePropfindResponse(bucketName: string, basePath: string, props: WebDAVProps[]): string {
	const responses = props.map((prop) => generatePropResponse(bucketName, basePath, prop)).join('\n');
	return `<?xml version="1.0" encoding="utf-8" ?>
  <D:multistatus xmlns:D="DAV:">
${responses}
  </D:multistatus>`;
}

function generatePropResponse(bucketName: string, basePath: string, prop: WebDAVProps): string {
	// 规范化路径，避免出现多余的斜杠导致客户端发起 // 路径
	const parts = [basePath, prop.displayname || ''].filter((p) => p);
	const resourcePath =
		'/' +
		parts
			.join('/')
			.replace(/\/+/g, '/')
			.replace(/\/$/, prop.resourcetype ? '/' : '');
	return `  <D:response>
    <D:href>${resourcePath}</D:href>
    <D:propstat>
      <D:prop>
        <D:creationdate>${prop.creationdate}</D:creationdate>
        <D:getcontentlength>${prop.getcontentlength}</D:getcontentlength>
        <D:getcontenttype>${prop.getcontenttype || ''}</D:getcontenttype>
        <D:getetag>${prop.getetag || ''}</D:getetag>
        <D:getlastmodified>${prop.getlastmodified}</D:getlastmodified>
        <D:resourcetype>${prop.resourcetype ? '<D:collection/>' : ''}</D:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>`;
}
