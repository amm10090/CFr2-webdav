// Lucide Icons - 精选文件类型图标
// https://lucide.dev

export const FILE_ICONS = {
	// 文档类 - FileText
	document: `<svg viewBox="0 0 24 24"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><line x1="16" x2="8" y1="13" y2="13"/><line x1="16" x2="8" y1="17" y2="17"/><line x1="10" x2="8" y1="9" y2="9"/></svg>`,

	// PDF - FileType
	pdf: `<svg viewBox="0 0 24 24"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><path d="M10 12h4v4h-4z"/></svg>`,

	// 代码类 - FileCode
	code: `<svg viewBox="0 0 24 24"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><path d="m10 13-2 2 2 2"/><path d="m14 17 2-2-2-2"/></svg>`,

	// 图片类 - Image
	image: `<svg viewBox="0 0 24 24"><rect width="18" height="18" x="3" y="3" rx="2" ry="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"/></svg>`,

	// 视频类 - Video
	video: `<svg viewBox="0 0 24 24"><path d="m22 8-6 4 6 4V8Z"/><rect width="14" height="12" x="2" y="6" rx="2" ry="2"/></svg>`,

	// 音频类 - Music
	audio: `<svg viewBox="0 0 24 24"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>`,

	// 压缩包 - Archive
	archive: `<svg viewBox="0 0 24 24"><rect width="16" height="20" x="4" y="2" rx="2" ry="2"/><path d="M9 2v20"/><path d="M15 2v20"/><path d="M9 6h6"/><path d="M9 10h6"/><path d="M9 14h6"/><path d="M9 18h6"/></svg>`,

	// 表格 - Sheet
	sheet: `<svg viewBox="0 0 24 24"><rect width="18" height="18" x="3" y="3" rx="2" ry="2"/><line x1="3" x2="21" y1="9" y2="9"/><line x1="3" x2="21" y1="15" y2="15"/><line x1="9" x2="9" y1="9" y2="21"/><line x1="15" x2="15" y1="9" y2="21"/></svg>`,

	// 演示文稿 - Presentation
	presentation: `<svg viewBox="0 0 24 24"><path d="M2 3h20"/><path d="M21 3v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V3"/><path d="m7 21 5-5 5 5"/></svg>`,

	// 默认文件 - File
	file: `<svg viewBox="0 0 24 24"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/></svg>`,
};

// 文件扩展名到图标的映射
export const EXT_TO_ICON: Record<string, keyof typeof FILE_ICONS> = {
	// 文档类
	pdf: 'pdf',
	doc: 'document',
	docx: 'document',
	txt: 'document',
	md: 'document',
	rtf: 'document',

	// 代码类
	js: 'code',
	ts: 'code',
	jsx: 'code',
	tsx: 'code',
	json: 'code',
	html: 'code',
	css: 'code',
	scss: 'code',
	py: 'code',
	java: 'code',
	cpp: 'code',
	c: 'code',
	go: 'code',
	rs: 'code',
	php: 'code',
	rb: 'code',
	sh: 'code',
	xml: 'code',
	yaml: 'code',
	yml: 'code',

	// 图片类
	jpg: 'image',
	jpeg: 'image',
	png: 'image',
	gif: 'image',
	webp: 'image',
	svg: 'image',
	bmp: 'image',
	ico: 'image',
	avif: 'image',
	tiff: 'image',

	// 视频类
	mp4: 'video',
	mov: 'video',
	webm: 'video',
	avi: 'video',
	mkv: 'video',
	flv: 'video',

	// 音频类
	mp3: 'audio',
	wav: 'audio',
	flac: 'audio',
	aac: 'audio',
	ogg: 'audio',
	m4a: 'audio',

	// 压缩包
	zip: 'archive',
	rar: 'archive',
	'7z': 'archive',
	tar: 'archive',
	gz: 'archive',
	bz2: 'archive',
	xz: 'archive',

	// 表格
	xls: 'sheet',
	xlsx: 'sheet',
	csv: 'sheet',

	// 演示文稿
	ppt: 'presentation',
	pptx: 'presentation',
};
