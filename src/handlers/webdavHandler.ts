// 文件名：src/handlers/webdavHandler.ts
import { listAll, fromR2Object, make_resource_path, generatePropfindResponse } from '../utils/webdavUtils';
import { logger } from '../utils/logger';
import { generateHTML, generateErrorHTML } from '../utils/templates';
import { WebDAVProps, Env, AuthContext } from '../types';
import {
	validateFileName,
	validateDirectoryName,
	validateFileSize,
	validateContentType,
	checkStorageQuota,
	updateStorageQuota,
	FILE_SIZE_LIMIT,
	TOTAL_STORAGE_LIMIT,
} from '../utils/validation';

const SUPPORT_METHODS = ['OPTIONS', 'PROPFIND', 'MKCOL', 'GET', 'HEAD', 'PUT', 'COPY', 'MOVE', 'DELETE'];
const DAV_CLASS = '1, 2';

export async function handleWebDAV(request: Request, env: Env, authContext: AuthContext): Promise<Response> {
	const { BUCKET, BUCKET_NAME } = env;

	try {
		switch (request.method) {
			case 'OPTIONS':
				return handleOptions();
			case 'HEAD':
				return await handleHead(request, BUCKET);
			case 'GET':
				return await handleGet(request, BUCKET, BUCKET_NAME, env);
			case 'PUT':
				return await handlePut(request, BUCKET, env);
			case 'DELETE':
				return await handleDelete(request, BUCKET, env);
			case 'MKCOL':
				return await handleMkcol(request, BUCKET);
			case 'PROPFIND':
				return await handlePropfind(request, BUCKET, BUCKET_NAME);
			case 'COPY':
				return await handleCopy(request, BUCKET, env);
			case 'MOVE':
				return await handleMove(request, BUCKET, env);
			default:
				return new Response('Method Not Allowed', {
					status: 405,
					headers: {
						Allow: SUPPORT_METHODS.join(', '),
						DAV: DAV_CLASS,
					},
				});
		}
	} catch (error) {
		const err = error as Error;
		logger.error('Error in WebDAV handling:', err.message);

		// Check if it's a validation error
		if (
			err.message.includes('not allowed') ||
			err.message.includes('too long') ||
			err.message.includes('exceeds limit') ||
			err.message.includes('quota exceeded') ||
			err.message.includes('invalid')
		) {
			return new Response(generateErrorHTML('Validation Error', err.message), {
				status: 400,
				headers: { 'Content-Type': 'text/html; charset=utf-8' },
			});
		}

		return new Response(generateErrorHTML('Internal Server Error', err.message), {
			status: 500,
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		});
	}
}

function handleOptions(): Response {
	// 仅声明 WebDAV 方法，CORS 由上层 setCORSHeaders 统一处理，避免通配符暴露
	return new Response(null, {
		status: 200,
		headers: {
			Allow: SUPPORT_METHODS.join(', '),
			DAV: DAV_CLASS,
		},
	});
}

async function handleHead(request: Request, bucket: R2Bucket): Promise<Response> {
	const resource_path = make_resource_path(request);
	const object = await bucket.head(resource_path);

	if (!object) {
		return new Response(null, { status: 404 });
	}

	return new Response(null, {
		status: 200,
		headers: {
			'Content-Type': object.httpMetadata?.contentType ?? 'application/octet-stream',
			'Content-Length': object.size.toString(),
			ETag: object.etag,
			'Last-Modified': object.uploaded.toUTCString(),
		},
	});
}

async function handleGet(request: Request, bucket: R2Bucket, bucketName: string, env: Env): Promise<Response> {
	const resource_path = make_resource_path(request);

	if (request.url.endsWith('/')) {
		return await handleDirectory(bucket, resource_path, bucketName, env);
	} else {
		return await handleFile(bucket, resource_path);
	}
}

async function handleDirectory(
	bucket: R2Bucket,
	resource_path: string,
	bucketName: string,
	env: Env,
): Promise<Response> {
	let items = [];

	if (resource_path !== '') {
		items.push({ name: '📁 ..', href: '../' });
	}

	try {
		for await (const object of listAll(bucket, resource_path)) {
			if (object.key === resource_path) continue;
			const isDirectory = object.customMetadata?.resourcetype === 'collection';
			const displayName = object.key.split('/').pop() || object.key;
			const href = `/${object.key}${isDirectory ? '/' : ''}`;
			items.push({ name: `${isDirectory ? '📁 ' : '📄 '}${displayName}`, href });
		}
	} catch (error) {
		const err = error as Error;
		logger.error('Error listing objects:', err.message);
		return new Response(generateErrorHTML('Error listing directory contents', err.message), {
			status: 500,
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		});
	}

	const page = generateHTML('WebDAV File Browser', items, resource_path || '/', env.DEMO_MODE === 'true');
	return new Response(page, {
		status: 200,
		headers: { 'Content-Type': 'text/html; charset=utf-8' },
	});
}

async function handleFile(bucket: R2Bucket, resource_path: string): Promise<Response> {
	try {
		const object = await bucket.get(resource_path);
		if (!object) {
			return new Response('Not Found', { status: 404 });
		}
		return new Response(object.body, {
			status: 200,
			headers: {
				'Content-Type': object.httpMetadata?.contentType ?? 'application/octet-stream',
				'Content-Length': object.size.toString(),
				ETag: object.etag,
				'Last-Modified': object.uploaded.toUTCString(),
			},
		});
	} catch (error) {
		const err = error as Error;
		logger.error('Error getting object:', err.message);
		return new Response(generateErrorHTML('Error retrieving file', err.message), {
			status: 500,
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		});
	}
}

async function handlePut(request: Request, bucket: R2Bucket, env: Env): Promise<Response> {
	const resource_path = make_resource_path(request);

	try {
		// Extract filename from path
		const filename = resource_path.split('/').pop() || '';

		// Validate filename
		validateFileName(filename);

		// Get file size from Content-Length header
		const contentLength = request.headers.get('Content-Length');
		if (!contentLength) {
			return new Response('Content-Length header required', { status: 411 });
		}

		const fileSize = parseInt(contentLength, 10);
		if (isNaN(fileSize)) {
			return new Response('Invalid Content-Length', { status: 400 });
		}

		// Validate file size
		const maxFileSize = env.MAX_FILE_SIZE ? parseInt(env.MAX_FILE_SIZE, 10) : FILE_SIZE_LIMIT;
		validateFileSize(fileSize, maxFileSize);

		// Validate Content-Type
		const contentType = request.headers.get('Content-Type');
		validateContentType(contentType);

		// Check storage quota
		const maxQuota = env.STORAGE_QUOTA ? parseInt(env.STORAGE_QUOTA, 10) : TOTAL_STORAGE_LIMIT;
		await checkStorageQuota(env.QUOTA_KV, fileSize, maxQuota);

		// Check if file already exists to handle quota update correctly
		const existingFile = await bucket.head(resource_path);
		const oldFileSize = existingFile?.size || 0;

		// Upload file
		const body = await request.arrayBuffer();
		await bucket.put(resource_path, body, {
			httpMetadata: {
				contentType: contentType || 'application/octet-stream',
			},
		});

		// Update quota (net change = new size - old size)
		const quotaDelta = fileSize - oldFileSize;
		const fileDelta = existingFile ? 0 : 1; // Only count as new file if didn't exist before
		if (quotaDelta !== 0 || fileDelta !== 0) {
			await updateStorageQuota(env.QUOTA_KV, quotaDelta, fileDelta);
		}

		return new Response('Created', { status: existingFile ? 204 : 201 });
	} catch (error) {
		const err = error as Error;
		logger.error('Error uploading file:', err.message);

		// Re-throw validation errors to be caught by main handler
		if (
			err.message.includes('not allowed') ||
			err.message.includes('too long') ||
			err.message.includes('exceeds limit') ||
			err.message.includes('quota exceeded')
		) {
			throw err;
		}

		return new Response(generateErrorHTML('Error uploading file', err.message), {
			status: 500,
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		});
	}
}

async function handleDelete(request: Request, bucket: R2Bucket, env: Env): Promise<Response> {
	const resource_path = make_resource_path(request);

	if (!resource_path) {
		return new Response('Bad Request: empty path', { status: 400 });
	}

	try {
		const head = await bucket.head(resource_path);
		if (!head) {
			return new Response('Not Found', { status: 404 });
		}

		// Delete the file
		await bucket.delete(resource_path);

		// Update quota (decrease)
		await updateStorageQuota(env.QUOTA_KV, -head.size, -1);

		return new Response('No Content', { status: 204 });
	} catch (error) {
		const err = error as Error;
		logger.error('Error deleting object:', err.message);
		return new Response(generateErrorHTML('Error deleting file', err.message), {
			status: 500,
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		});
	}
}

async function handleMkcol(request: Request, bucket: R2Bucket): Promise<Response> {
	const resource_path = make_resource_path(request);

	if (resource_path === '') {
		return new Response('Method Not Allowed', { status: 405 });
	}

	try {
		// Extract directory name and validate
		const dirname = resource_path.split('/').pop() || '';
		if (dirname) {
			validateDirectoryName(dirname);
		}

		await bucket.put(resource_path + '/', new Uint8Array(), {
			customMetadata: { resourcetype: 'collection' },
		});
		return new Response('Created', { status: 201 });
	} catch (error) {
		const err = error as Error;
		logger.error('Error creating collection:', err.message);

		// Re-throw validation errors
		if (err.message.includes('not allowed') || err.message.includes('too long') || err.message.includes('invalid')) {
			throw err;
		}

		return new Response(generateErrorHTML('Error creating collection', err.message), {
			status: 500,
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		});
	}
}

async function handlePropfind(request: Request, bucket: R2Bucket, bucketName: string): Promise<Response> {
	const resource_path = make_resource_path(request);
	const depth = request.headers.get('Depth') || 'infinity';

	try {
		const props: WebDAVProps[] = [];
		if (depth !== '0') {
			for await (const object of listAll(bucket, resource_path)) {
				props.push(fromR2Object(object));
			}
		} else {
			const object = await bucket.head(resource_path);
			if (object) {
				props.push(fromR2Object(object));
			} else {
				return new Response('Not Found', { status: 404 });
			}
		}

		const xml = generatePropfindResponse(bucketName, resource_path, props);
		logger.info('Generated XML for PROPFIND:', xml);
		return new Response(xml, {
			status: 207,
			headers: { 'Content-Type': 'application/xml; charset=utf-8' },
		});
	} catch (error) {
		const err = error as Error;
		logger.error('Error in PROPFIND:', err.message);
		return new Response(generateErrorHTML('Error in PROPFIND', err.message), {
			status: 500,
			headers: { 'Content-Type': 'application/xml; charset=utf-8' },
		});
	}
}

async function handleCopy(request: Request, bucket: R2Bucket, env: Env): Promise<Response> {
	const sourcePath = make_resource_path(request);
	const destinationHeader = request.headers.get('Destination');
	if (!destinationHeader) {
		return new Response('Bad Request: Destination header is missing', { status: 400 });
	}
	const destinationUrl = new URL(destinationHeader);
	const destinationPath = make_resource_path(new Request(destinationUrl));

	try {
		const sourceObject = await bucket.get(sourcePath);
		if (!sourceObject) {
			return new Response('Not Found', { status: 404 });
		}

		// Validate destination filename
		const destFilename = destinationPath.split('/').pop() || '';
		validateFileName(destFilename);

		// Check quota for copy operation（只校验净新增部分，避免覆盖误报）
		const maxQuota = env.STORAGE_QUOTA ? parseInt(env.STORAGE_QUOTA, 10) : TOTAL_STORAGE_LIMIT;
		const existingDest = await bucket.head(destinationPath);
		const oldDestSize = existingDest?.size || 0;
		const quotaDeltaForCheck = Math.max(0, sourceObject.size - oldDestSize);
		await checkStorageQuota(env.QUOTA_KV, quotaDeltaForCheck, maxQuota);

		await bucket.put(destinationPath, sourceObject.body, {
			httpMetadata: sourceObject.httpMetadata,
			customMetadata: sourceObject.customMetadata,
		});

		// Update quota (new file size - old file size if overwriting)
		const quotaDeltaPersist = sourceObject.size - oldDestSize;
		const fileDelta = existingDest ? 0 : 1;
		if (quotaDeltaPersist !== 0 || fileDelta !== 0) {
			await updateStorageQuota(env.QUOTA_KV, quotaDeltaPersist, fileDelta);
		}

		return new Response('Created', { status: existingDest ? 204 : 201 });
	} catch (error) {
		const err = error as Error;
		logger.error('Error copying object:', err.message);

		// Re-throw validation errors
		if (
			err.message.includes('not allowed') ||
			err.message.includes('exceeds limit') ||
			err.message.includes('quota exceeded')
		) {
			throw err;
		}

		return new Response(generateErrorHTML('Error copying file', err.message), {
			status: 500,
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		});
	}
}

async function handleMove(request: Request, bucket: R2Bucket, env: Env): Promise<Response> {
	const sourcePath = make_resource_path(request);
	const destinationHeader = request.headers.get('Destination');
	if (!destinationHeader) {
		return new Response('Bad Request: Destination header is missing', { status: 400 });
	}
	const destinationUrl = new URL(destinationHeader);
	const destinationPath = make_resource_path(new Request(destinationUrl));

	// 防止自拷贝导致数据被删除
	if (sourcePath === destinationPath) {
		return new Response('Bad Request: source and destination are the same', { status: 400 });
	}

	try {
		const sourceObject = await bucket.get(sourcePath);
		if (!sourceObject) {
			return new Response('Not Found', { status: 404 });
		}

		// Validate destination filename
		const destFilename = destinationPath.split('/').pop() || '';
		validateFileName(destFilename);

		// Check if destination already exists
		const existingDest = await bucket.head(destinationPath);
		const oldDestSize = existingDest?.size || 0;

		// Move is copy + delete
		await bucket.put(destinationPath, sourceObject.body, {
			httpMetadata: sourceObject.httpMetadata,
			customMetadata: sourceObject.customMetadata,
		});

		await bucket.delete(sourcePath);

		// Update quota
		// Net change = (new dest size - old dest size) - source size
		// File count change = +1 if dest was new, -1 for source deletion
		const quotaDelta = -oldDestSize; // 删除源文件与写入目标相互抵消，仅扣除被覆盖的旧目标大小
		const fileDelta = (existingDest ? 0 : 1) - 1; // +1 for new dest, -1 for deleted source
		if (quotaDelta !== 0 || fileDelta !== 0) {
			await updateStorageQuota(env.QUOTA_KV, quotaDelta, fileDelta);
		}

		return new Response('No Content', { status: 204 });
	} catch (error) {
		const err = error as Error;
		logger.error('Error moving object:', err.message);

		// Re-throw validation errors
		if (err.message.includes('not allowed')) {
			throw err;
		}

		return new Response(generateErrorHTML('Error moving file', err.message), {
			status: 500,
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		});
	}
}
