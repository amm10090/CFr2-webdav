// Translation types
export type Language = 'zh' | 'en';

export type TranslationKey =
	| 'title'
	| 'searchPlaceholder'
	| 'gridView'
	| 'listView'
	| 'disconnect'
	| 'refresh'
	| 'newFolder'
	| 'upload'
	| 'dropToUpload'
	| 'connectionError'
	| 'loading'
	| 'emptyFolder'
	| 'emptyFolderDesc'
	| 'name'
	| 'size'
	| 'lastModified'
	| 'actions'
	| 'deleteConfirm'
	| 'deleteSuccess'
	| 'deleteFailed'
	| 'uploadSuccess'
	| 'uploadFailed'
	| 'createFolderPrompt'
	| 'createFolderSuccess'
	| 'createFolderFailed'
	| 'settingsTitle'
	| 'serverUrl'
	| 'username'
	| 'password'
	| 'corsTip'
	| 'saveConnect'
	| 'logout'
	| 'logoutConfirm'
	| 'download'
	| 'delete'
	| 'language'
	| 'appearance'
	| 'themeLight'
	| 'themeDark'
	| 'themeSystem'
	| 'unauthorized'
	| 'webdavError'
	| 'uploadQueue'
	| 'queueEmpty'
	| 'cancelUpload'
	| 'retryUpload'
	| 'clearCompleted'
	| 'pending'
	| 'uploading'
	| 'completed'
	| 'failed'
	| 'canceled'
	| 'selectedFiles'
	| 'fileTypeNotAllowed'
	| 'fileTooLarge'
	| 'fileEmpty'
	| 'multipleFilesSupported'
	| 'uploadInProgress';

export type Translations = Record<Language, Record<TranslationKey, string>>;

// Translation data
export const TRANSLATIONS: Translations = {
	zh: {
		title: 'R2 WebDAV',
		searchPlaceholder: '搜索文件...',
		gridView: '网格视图',
		listView: '列表视图',
		disconnect: '断开连接',
		refresh: '刷新',
		newFolder: '新建文件夹',
		upload: '上传文件',
		dropToUpload: '释放文件以上传',
		connectionError: '连接错误',
		loading: '加载内容中...',
		emptyFolder: '此文件夹为空',
		emptyFolderDesc: '新建文件夹或拖拽文件到此处开始使用。',
		name: '名称',
		size: '大小',
		lastModified: '最后修改',
		actions: '操作',
		deleteConfirm: '确定要删除 {name} 吗？',
		deleteSuccess: '删除成功',
		deleteFailed: '删除失败',
		uploadSuccess: '上传成功',
		uploadFailed: '上传失败',
		createFolderPrompt: '输入文件夹名称:',
		createFolderSuccess: '文件夹创建成功',
		createFolderFailed: '创建失败',
		settingsTitle: '设置',
		serverUrl: 'Worker 地址 (URL)',
		username: '用户名',
		password: '密码',
		corsTip: '提示: 确保你的 Cloudflare Worker 允许 CORS (OPTIONS 请求) 以支持浏览器访问。',
		saveConnect: '保存并连接',
		logout: '退出登录',
		logoutConfirm: '确定要退出登录吗？',
		download: '下载',
		delete: '删除',
		language: '语言',
		appearance: '外观',
		themeLight: '浅色',
		themeDark: '深色',
		themeSystem: '跟随系统',
		unauthorized: '未授权。请检查您的用户名和密码。',
		webdavError: 'WebDAV 错误',
		uploadQueue: '上传队列',
		queueEmpty: '暂无上传任务',
		cancelUpload: '取消',
		retryUpload: '重试',
		clearCompleted: '清除已完成',
		pending: '等待中',
		uploading: '上传中',
		completed: '已完成',
		failed: '失败',
		canceled: '已取消',
		selectedFiles: '已选择 {count} 个文件,总计 {size}',
		fileTypeNotAllowed: '不支持的文件类型',
		fileTooLarge: '文件大小超过限制',
		fileEmpty: '文件不能为空',
		multipleFilesSupported: '支持多文件上传',
		uploadInProgress: '文件正在上传中,确定要离开吗?',
	},
	en: {
		title: 'R2 WebDAV',
		searchPlaceholder: 'Search files...',
		gridView: 'Grid View',
		listView: 'List View',
		disconnect: 'Disconnect',
		refresh: 'Refresh',
		newFolder: 'New Folder',
		upload: 'Upload',
		dropToUpload: 'Drop files to upload',
		connectionError: 'Connection Error',
		loading: 'Fetching contents...',
		emptyFolder: 'This folder is empty',
		emptyFolderDesc: 'Get started by creating a new folder or dragging files here to upload.',
		name: 'Name',
		size: 'Size',
		lastModified: 'Last Modified',
		actions: 'Actions',
		deleteConfirm: 'Are you sure you want to delete {name}?',
		deleteSuccess: 'Deleted successfully',
		deleteFailed: 'Delete failed',
		uploadSuccess: 'Uploaded successfully',
		uploadFailed: 'Upload failed',
		createFolderPrompt: 'Enter folder name:',
		createFolderSuccess: 'Folder created successfully',
		createFolderFailed: 'Failed to create folder',
		settingsTitle: 'Connection Settings',
		serverUrl: 'Worker URL',
		username: 'Username',
		password: 'Password',
		corsTip: 'Tip: Ensure your Cloudflare Worker handles OPTIONS requests (CORS) to allow browser access.',
		saveConnect: 'Save & Connect',
		logout: 'Logout',
		logoutConfirm: 'Are you sure you want to logout?',
		download: 'Download',
		delete: 'Delete',
		language: 'Language',
		appearance: 'Appearance',
		themeLight: 'Light',
		themeDark: 'Dark',
		themeSystem: 'System',
		unauthorized: 'Unauthorized. Please check your credentials.',
		webdavError: 'WebDAV Error',
		uploadQueue: 'Upload Queue',
		queueEmpty: 'No uploads yet',
		cancelUpload: 'Cancel',
		retryUpload: 'Retry',
		clearCompleted: 'Clear Completed',
		pending: 'Pending',
		uploading: 'Uploading',
		completed: 'Completed',
		failed: 'Failed',
		canceled: 'Canceled',
		selectedFiles: '{count} files selected, {size} total',
		fileTypeNotAllowed: 'File type not allowed',
		fileTooLarge: 'File size exceeds limit',
		fileEmpty: 'File cannot be empty',
		multipleFilesSupported: 'Multiple files supported',
		uploadInProgress: 'Files are uploading. Are you sure you want to leave?',
	},
};
