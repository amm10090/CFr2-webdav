export function generateHTML(title: string, items: { name: string; href: string }[], currentPath = '/'): string {
	// The heavy UI logic runs on the client; we pass minimal initial data to avoid duplicate fetch.
	const initialItems = JSON.stringify(items || []);
	const safeTitle = title || 'R2 WebDAV';

	return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${safeTitle}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
    };
  </script>
  <style>
    * { box-sizing: border-box; }
    .scrollbar-hide::-webkit-scrollbar { display: none; }
    .scrollbar-hide { -ms-overflow-style: none; scrollbar-width: none; }
    .animate-fade-in { animation: fade 0.2s ease-in; }
    @keyframes fade { from {opacity: 0;} to {opacity: 1;} }
  </style>
</head>
<body class="bg-gray-50 dark:bg-gray-950 text-gray-800 dark:text-gray-100">
  <div id="app" class="min-h-screen flex flex-col"></div>
  <script>
    // ---- Translations ----
    const TRANSLATIONS = {
      zh: {
        title: 'R2 WebDAV',
        demoMode: '演示模式',
        liveMode: '在线模式',
        searchPlaceholder: '搜索文件...',
        switchToLive: '切换到在线模式',
        liveActive: '在线模式运行中',
        gridView: '网格视图',
        listView: '列表视图',
        disconnect: '断开连接',
        refresh: '刷新',
        newFolder: '新建文件夹',
        upload: '上传文件',
        dropToUpload: '释放文件以上传',
        connectionError: '连接错误',
        demoNote: '注意：演示模式模拟服务器响应。请在设置中切换到在线模式。',
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
        useDemo: '使用演示模式',
        saveConnect: '保存并连接',
        download: '下载',
        delete: '删除',
        language: '语言',
        appearance: '外观',
        themeLight: '浅色',
        themeDark: '深色',
        themeSystem: '跟随系统',
        unauthorized: '未授权。请检查您的用户名和密码。',
        webdavError: 'WebDAV 错误',
      },
      en: {
        title: 'R2 WebDAV',
        demoMode: 'DEMO MODE',
        liveMode: 'LIVE MODE',
        searchPlaceholder: 'Search files...',
        switchToLive: 'Switch to Live',
        liveActive: 'Live Active',
        gridView: 'Grid View',
        listView: 'List View',
        disconnect: 'Disconnect',
        refresh: 'Refresh',
        newFolder: 'New Folder',
        upload: 'Upload',
        dropToUpload: 'Drop files to upload',
        connectionError: 'Connection Error',
        demoNote: 'Note: Demo mode simulates responses. Switch to Live mode in settings.',
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
        useDemo: 'Use Demo Mode',
        saveConnect: 'Save & Connect',
        download: 'Download',
        delete: 'Delete',
        language: 'Language',
        appearance: 'Appearance',
        themeLight: 'Light',
        themeDark: 'Dark',
        themeSystem: 'System',
        unauthorized: 'Unauthorized. Please check your credentials.',
        webdavError: 'WebDAV Error',
      },
    };

    // ---- Mock data for demo ----
    const MOCK_FILES = {
      "/": ${initialItems},
    };

    // ---- State ----
    const app = document.getElementById('app');
    const initialPath = "${currentPath}";
    let currentPath = initialPath || "/";
    let files = ${initialItems};
    let loading = false;
    let error = null;
    let viewMode = 'grid';
    let isDemo = true;
    let isDragging = false;
    const storedLang = localStorage.getItem('app_lang');
    const storedTheme = localStorage.getItem('app_theme');
    const storedAuth = JSON.parse(localStorage.getItem('app_auth') || '{}');
    let lang = storedLang === 'en' || storedLang === 'zh'
      ? storedLang
      : (navigator.language || '').toLowerCase().startsWith('en') ? 'en' : 'zh';
    let theme = storedTheme || 'system';
    let auth = {
      url: storedAuth.url || window.location.origin,
      username: storedAuth.username || '',
      password: storedAuth.password || '',
    };

    const t = () => TRANSLATIONS[lang];

    // ---- Helpers ----
    const formatBytes = (bytes) => {
      if (bytes === undefined || bytes === null) return '-';
      if (bytes === 0) return '0 Bytes';
      const k = 1024;
      const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    const formatDate = (dateString) => {
      if (!dateString) return '-';
      try {
        return new Date(dateString).toLocaleDateString(
          lang === 'zh' ? 'zh-CN' : 'en-US',
          { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }
        );
      } catch (_) {
        return dateString;
      }
    };

    const parseWebDAVXML = (xmlText) => {
      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(xmlText, 'text/xml');
      const responses = xmlDoc.querySelectorAll('response');
      const entries = [];

      responses.forEach((response) => {
        const href = response.querySelector('href')?.textContent || '';
        if (!href) return;
        const propstat = response.querySelector('propstat');
        if (!propstat) return;
        const status = propstat.querySelector('status')?.textContent || '';
        if (!status.includes('200')) return;
        const prop = propstat.querySelector('prop');
        if (!prop) return;
        const resourcetype = prop.querySelector('resourcetype');
        const isCollection = resourcetype?.querySelector('collection');
        const type = isCollection ? 'directory' : 'file';
        const getcontentlength = prop.querySelector('getcontentlength')?.textContent;
        const getlastmodified = prop.querySelector('getlastmodified')?.textContent;
        const decodedHref = decodeURIComponent(href);
        let name = decodedHref.split('/').filter((p) => p).pop() || '';
        entries.push({
          name: name || (decodedHref === '/' ? 'Root' : decodedHref),
          type,
          size: getcontentlength ? parseInt(getcontentlength) : 0,
          lastModified: getlastmodified || '',
          href: decodedHref,
        });
      });

      return entries;
    };

    const renderFileIcon = (file, size = 48) => {
      const type = file.type;
      if (type === 'directory') {
        return \`<svg class="text-blue-500 fill-blue-50 dark:fill-blue-900/30" width="\${size}" height="\${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/></svg>\`;
      }
      const ext = (file.name.split('.').pop() || '').toLowerCase();
      const icon = (color) => \`<svg width="\${size}" height="\${size}" fill="none" stroke="currentColor" stroke-width="2" class="\${color}" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><polyline points="14 2 14 8 20 8"/></svg>\`;
      if (['jpg','png','gif','jpeg','svg','webp'].includes(ext)) return icon('text-purple-500');
      if (['mp4','mov','webm'].includes(ext)) return icon('text-red-500');
      if (['mp3','wav','flac'].includes(ext)) return icon('text-yellow-500');
      if (['pdf','txt','doc','docx','md','json'].includes(ext)) return icon('text-gray-500 dark:text-gray-400');
      if (['zip','rar','7z','tar','gz'].includes(ext)) return icon('text-orange-500');
      return icon('text-gray-400');
    };

    const applyTheme = () => {
      const root = document.documentElement;
      const isDark = theme === 'dark'
        || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
      root.classList.toggle('dark', isDark);
    };

    applyTheme();
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
      if (theme === 'system') applyTheme();
    });

    // ---- Data fetchers ----
    const getHeaders = () => {
      const headers = { Accept: 'application/xml, text/xml' };
      if (auth.username && auth.password) {
        headers['Authorization'] = 'Basic ' + btoa(auth.username + ':' + auth.password);
      }
      return headers;
    };

    const fetchFiles = async (path) => {
      loading = true; error = null; render();
      try {
        if (isDemo) {
          await new Promise((r) => setTimeout(r, 400));
          files = MOCK_FILES[path] || [];
        } else {
          const url = auth.url.replace(/\\/$/, '') + path;
          const res = await fetch(url, { method: 'PROPFIND', headers: { ...getHeaders(), Depth: '1' } });
          if (res.status === 401) throw new Error(t().unauthorized);
          if (!res.ok) throw new Error(t().webdavError + ': ' + res.statusText);
          const text = await res.text();
          let parsed = parseWebDAVXML(text);
          parsed = parsed.filter((f) => {
            const entryPath = f.href.endsWith('/') ? f.href : f.href + '/';
            const currentDir = path.endsWith('/') ? path : path + '/';
            return entryPath !== currentDir && f.href !== path;
          });
          files = parsed;
        }
      } catch (e) {
        error = e.message || t().connectionError;
      } finally {
        loading = false;
        render();
      }
    };

    const handleDelete = async (file) => {
      if (!confirm(t().deleteConfirm.replace('{name}', file.name))) return;
      if (isDemo) {
        files = files.filter((f) => f.href !== file.href);
        render();
        return;
      }
      loading = true; render();
      try {
        const url = auth.url.replace(/\\/$/, '') + file.href;
        const res = await fetch(url, { method: 'DELETE', headers: getHeaders() });
        if (!res.ok) throw new Error(t().deleteFailed);
        await fetchFiles(currentPath);
      } catch (e) {
        alert(e.message || t().deleteFailed);
        loading = false; render();
      }
    };

    const handleCreateFolder = async () => {
      const name = prompt(t().createFolderPrompt);
      if (!name) return;
      if (isDemo) {
        files.push({ name, type: 'directory', href: (currentPath.endsWith('/') ? currentPath : currentPath + '/') + name + '/', lastModified: new Date().toISOString() });
        render();
        return;
      }
      loading = true; render();
      try {
        const safePath = currentPath.endsWith('/') ? currentPath : currentPath + '/';
        const url = auth.url.replace(/\\/$/, '') + safePath + name;
        const res = await fetch(url, { method: 'MKCOL', headers: getHeaders() });
        if (!res.ok) throw new Error(t().createFolderFailed);
        await fetchFiles(currentPath);
      } catch (e) {
        alert(e.message || t().createFolderFailed);
        loading = false; render();
      }
    };

    const uploadFile = async (file) => {
      if (isDemo) {
        alert(t().uploadSuccess + ': ' + file.name);
        return;
      }
      loading = true; render();
      try {
        const safePath = currentPath.endsWith('/') ? currentPath : currentPath + '/';
        const url = auth.url.replace(/\\/$/, '') + safePath + file.name;
        const res = await fetch(url, { method: 'PUT', headers: getHeaders(), body: file });
        if (!res.ok) throw new Error(t().uploadFailed);
        await fetchFiles(currentPath);
      } catch (e) {
        alert(e.message || t().uploadFailed);
        loading = false; render();
      }
    };

    // ---- UI ----
    const render = () => {
      const pathParts = currentPath.split('/').filter(Boolean);
      const filtered = files.filter((f) => f.name.toLowerCase().includes((document.getElementById('searchInput')?.value || '').toLowerCase()));
      const sorted = [...filtered].sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name) : a.type === 'directory' ? -1 : 1));
      const tdict = t();
      applyTheme();

      app.innerHTML = \`
        <header class="bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 sticky top-0 z-20 shadow-sm">
          <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <div class="flex items-center space-x-3">
              <div class="bg-gradient-to-br from-blue-600 to-indigo-600 p-2 rounded-lg shadow-sm">
                <svg class="text-white" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 14v4c0 .55.45 1 1 1h3v-5H4Zm0-4h4V5H5c-.55 0-1 .45-1 1v4Zm6 0h4V5h-4v5Zm0 10h4v-5h-4v5Zm6 0h3c.55 0 1-.45 1-1v-4h-4v5Zm0-10h4V6c0-.55-.45-1-1-1h-3v5Z"/></svg>
              </div>
              <div>
                <h1 class="text-xl font-bold text-gray-900 dark:text-white leading-tight tracking-tight">\${tdict.title}</h1>
                <div class="flex items-center space-x-2">
                  <span class="inline-block w-2 h-2 rounded-full \${isDemo ? 'bg-amber-400' : 'bg-green-500'}"></span>
                  <p class="text-xs text-gray-500 dark:text-gray-400 font-medium tracking-wide">\${isDemo ? tdict.demoMode : (auth.url || '').replace(/^https?:\\/\\//,'')}</p>
                </div>
              </div>
            </div>
            <div class="flex-1 max-w-xl mx-8 hidden md:block">
              <div class="relative group">
                <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <svg class="h-5 w-5 text-gray-400 dark:text-gray-500 group-focus-within:text-blue-500" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"></circle><line x1="16.5" y1="16.5" x2="20" y2="20"></line></svg>
                </div>
                <input id="searchInput" type="text" placeholder="\${tdict.searchPlaceholder}"
                  class="block w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-700 rounded-lg leading-5 bg-gray-50 dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:bg-white dark:focus:bg-gray-800 focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 sm:text-sm transition"
                  value="\${document.getElementById('searchInput')?.value || ''}">
              </div>
            </div>
            <div class="flex items-center space-x-2">
              <div class="flex bg-gray-100 dark:bg-gray-800 p-1 rounded-lg border border-gray-200 dark:border-gray-700">
                <button data-view="grid" class="p-1.5 rounded-md \${viewMode === 'grid' ? 'bg-white dark:bg-gray-700 shadow-sm text-blue-600 dark:text-blue-400' : 'text-gray-500 dark:text-gray-400'}" title="\${tdict.gridView}">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                </button>
                <button data-view="list" class="p-1.5 rounded-md \${viewMode === 'list' ? 'bg-white dark:bg-gray-700 shadow-sm text-blue-600 dark:text-blue-400' : 'text-gray-500 dark:text-gray-400'}" title="\${tdict.listView}">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>
                </button>
              </div>
              <div class="h-6 w-px bg-gray-300 dark:bg-gray-700 mx-2"></div>
              <button id="openSettings" class="p-2 text-gray-500 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 rounded-full hover:bg-blue-50 dark:hover:bg-gray-800 transition" title="\${tdict.settingsTitle}">
                <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.09a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/></svg>
              </button>
            </div>
          </div>
        </header>

        <div class="bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 shadow-sm">
          <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3 flex items-center justify-between gap-4">
            <nav class="flex items-center text-sm text-gray-500 dark:text-gray-400 overflow-x-auto whitespace-nowrap scrollbar-hide">
              <button class="p-1.5 rounded-md \${currentPath === '/' ? 'text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20' : 'hover:bg-gray-100 dark:hover:bg-gray-800'}" id="breadcrumb-root">
                <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a1 1 0 0 1-1 1h-5a1 1 0 0 1-1-1v-4H9v4a1 1 0 0 1-1 1H3V9Z"/></svg>
              </button>
              \${pathParts.map((part, idx) => \`
                <div class="flex items-center">
                  <svg width="14" height="14" class="mx-1 text-gray-400 dark:text-gray-600" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg>
                  <button class="px-2 py-1 rounded-md hover:bg-gray-100 dark:hover:bg-gray-800 text-gray-700 dark:text-gray-300" data-bc="\${idx}">\${decodeURIComponent(part)}</button>
                </div>
              \`).join('')}
            </nav>

            <div class="flex items-center space-x-2">
              <button id="btnRefresh" class="p-2 text-gray-500 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-lg" \${loading ? 'disabled' : ''} title="\${tdict.refresh}">
                <svg class="\${loading ? 'animate-spin' : ''}" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.13-3.36L23 10M1 14l5.36 4.36A9 9 0 0 0 20.49 15"/></svg>
              </button>
              <button id="btnMkcol" class="hidden sm:flex items-center space-x-1.5 px-3 py-1.5 text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">
                <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 5h4l2 3h10v11H4z"/><path d="M12 10v6M9 13h6"/></svg>
                <span>\${tdict.newFolder}</span>
              </button>
              <label class="flex items-center space-x-1.5 px-3 py-1.5 text-sm font-medium text-white bg-blue-600 dark:bg-blue-500 rounded-lg cursor-pointer hover:bg-blue-700 dark:hover:bg-blue-600">
                <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 17v2h16v-2M12 12v9m-5-9 5-5 5 5"/></svg>
                <span class="hidden sm:inline">\${tdict.upload}</span>
                <input id="fileInput" type="file" class="hidden" />
              </label>
            </div>
          </div>
        </div>

        <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
          \${error ? \`
            <div class="mb-6 bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 p-4 rounded-r-lg flex items-start animate-fade-in">
              <svg class="text-red-500 dark:text-red-400 mt-0.5 mr-3" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
              <div>
                <h3 class="text-sm font-medium text-red-800 dark:text-red-200">\${tdict.connectionError}</h3>
                <p class="text-sm text-red-700 dark:text-red-300 mt-1">\${error}</p>
                \${isDemo ? '<p class="text-xs text-red-600 dark:text-red-400 mt-2">' + tdict.demoNote + '</p>' : ''}
              </div>
            </div>\` : ''}

          \${loading && files.length === 0 ? \`
            <div class="flex flex-col items-center justify-center py-32 opacity-75">
              <svg class="animate-spin text-blue-500 dark:text-blue-400 mb-4" width="48" height="48" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10"></circle><path d="M4 12a8 8 0 0 1 8-8" class="opacity-75"/></svg>
              <p class="text-gray-500 dark:text-gray-400 font-medium">\${tdict.loading}</p>
            </div>\`
          : sorted.length === 0 ? \`
            <div class="text-center py-32 border-2 border-dashed border-gray-300 dark:border-gray-700 rounded-2xl bg-gray-50/50 dark:bg-gray-800/50">
              <div class="mx-auto h-16 w-16 text-gray-300 dark:text-gray-600 mb-4">
                <svg width="64" height="64" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 5h4l2 3h10v11H4z"/><path d="M12 10v6M9 13h6"/></svg>
              </div>
              <h3 class="text-lg font-medium text-gray-900 dark:text-gray-100">\${tdict.emptyFolder}</h3>
              <p class="mt-2 text-sm text-gray-500 dark:text-gray-400 max-w-sm mx-auto">\${tdict.emptyFolderDesc}</p>
            </div>\`
          : viewMode === 'grid' ? \`
            <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-4">
              \${sorted.map(file => \`
                <div data-href="\${file.href}" data-type="\${file.type}"
                  class="group relative bg-white dark:bg-gray-800 p-4 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 hover:shadow-md hover:border-blue-400 dark:hover:border-blue-500 hover:bg-gray-50 dark:hover:bg-gray-750 transition cursor-pointer flex flex-col items-center text-center aspect-[4/5] justify-between">
                  <div class="flex-1 flex items-center justify-center w-full transform group-hover:scale-105 transition">
                    \${renderFileIcon(file)}
                  </div>
                  <div class="w-full mt-3">
                    <h3 class="text-sm font-medium text-gray-900 dark:text-gray-100 truncate px-1" title="\${file.name}">\${file.name}</h3>
                    <div class="mt-1 text-xs text-gray-400 dark:text-gray-500 font-normal">\${file.type === 'directory' ? formatDate(file.lastModified).split(' ')[0] : formatBytes(file.size)}</div>
                  </div>
                  <button data-del="\${file.href}" class="absolute top-2 right-2 p-1.5 bg-white/90 dark:bg-gray-700/90 text-gray-400 dark:text-gray-300 hover:text-red-500 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30 rounded-full shadow-sm opacity-0 group-hover:opacity-100 transition transform scale-90 group-hover:scale-100" title="\${tdict.delete}">
                    <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                  </button>
                </div>\`).join('')}
            </div>\`
          : \`
            <div class="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-sm overflow-hidden">
              <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead class="bg-gray-50 dark:bg-gray-900/50">
                  <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">\${tdict.name}</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider w-32 sm:table-cell hidden">\${tdict.size}</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider w-48 sm:table-cell hidden">\${tdict.lastModified}</th>
                    <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider w-24">\${tdict.actions}</th>
                  </tr>
                </thead>
                <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                  \${sorted.map(file => \`
                    <tr data-href="\${file.href}" data-type="\${file.type}" class="hover:bg-blue-50/50 dark:hover:bg-blue-900/10 cursor-pointer transition group">
                      <td class="px-6 py-4 whitespace-nowrap">
                        <div class="flex items-center">
                          <div class="flex-shrink-0 h-10 w-10 flex items-center justify-center">
                            \${renderFileIcon(file, 32)}
                          </div>
                          <div class="ml-4">
                            <div class="text-sm font-medium text-gray-900 dark:text-gray-100">\${file.name}</div>
                            <div class="text-xs text-gray-500 dark:text-gray-400 sm:hidden">\${file.type === 'directory' ? 'Folder' : formatBytes(file.size)} • \${formatDate(file.lastModified)}</div>
                          </div>
                        </div>
                      </td>
                      <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400 hidden sm:table-cell">\${file.type === 'directory' ? '-' : formatBytes(file.size)}</td>
                      <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400 hidden sm:table-cell">\${formatDate(file.lastModified)}</td>
                      <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <div class="flex items-center justify-end space-x-2 opacity-0 group-hover:opacity-100 transition">
                          \${file.type !== 'directory' ? \`
                            <button data-dl="\${file.href}" class="text-blue-600 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-200 p-1 hover:bg-blue-100 dark:hover:bg-blue-900/30 rounded" title="\${tdict.download}">
                              <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 17v2h16v-2"/><path d="M12 12v9m-5-9 5-5 5 5"/></svg>
                            </button>\` : ''}
                          <button data-del="\${file.href}" class="text-red-600 dark:text-red-400 hover:text-red-900 dark:hover:text-red-200 p-1 hover:bg-red-100 dark:hover:bg-red-900/30 rounded" title="\${tdict.delete}">
                            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                          </button>
                        </div>
                      </td>
                    </tr>\`).join('')}
                </tbody>
              </table>
            </div>\`}
        </main>

        \${isDragging ? \`
          <div class="fixed inset-0 z-50 bg-blue-500/10 backdrop-blur-sm border-4 border-blue-500 border-dashed m-4 rounded-2xl flex items-center justify-center pointer-events-none">
            <div class="bg-white dark:bg-gray-800 p-6 rounded-xl shadow-xl flex flex-col items-center animate-bounce border border-gray-200 dark:border-gray-700">
              <svg class="text-blue-600 dark:text-blue-400 mb-2" width="48" height="48" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 17v2h16v-2M12 12v9m-5-9 5-5 5 5"/></svg>
              <span class="text-xl font-bold text-blue-800 dark:text-blue-300">\${tdict.dropToUpload}</span>
            </div>
          </div>\` : ''}

        <div id="modal" class="fixed inset-0 z-50 hidden items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div class="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-md w-full overflow-hidden border border-gray-100 dark:border-gray-700">
            <div class="px-6 py-4 bg-gradient-to-r from-gray-50 to-white dark:from-gray-800 dark:to-gray-800 border-b border-gray-100 dark:border-gray-700 flex justify-between items-center">
              <div class="flex items-center space-x-2">
                <svg class="text-gray-500 dark:text-gray-400" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.09a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/></svg>
                <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100">\${tdict.settingsTitle}</h3>
              </div>
              <button id="modalClose" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 transition">&times;</button>
            </div>
            <div class="p-6 space-y-5 max-h-[80vh] overflow-y-auto">
              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5 flex items-center gap-1.5">
                    <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="2" y="5" width="20" height="14" rx="2" ry="2"/><line x1="12" y1="9" x2="12" y2="15"/></svg>
                    \${tdict.appearance}
                  </label>
                  <select id="selectTheme" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                    <option value="light">\${tdict.themeLight}</option>
                    <option value="dark">\${tdict.themeDark}</option>
                    <option value="system">\${tdict.themeSystem}</option>
                  </select>
                </div>
                <div>
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5 flex items-center gap-1.5">
                    <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M5 8h14M5 12h14M5 16h14"/></svg>
                    \${tdict.language}
                  </label>
                  <select id="selectLang" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                    <option value="zh">中文</option>
                    <option value="en">English</option>
                  </select>
                </div>
              </div>
              <hr class="border-gray-200 dark:border-gray-700" />
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">\${tdict.serverUrl}</label>
                <input id="inputUrl" type="text" class="w-full pl-3 pr-3 py-2.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" placeholder="https://your-worker.workers.dev" value="\${auth.url || ''}" />
              </div>
              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">\${tdict.username}</label>
                  <input id="inputUser" type="text" class="w-full px-3 py-2.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" value="\${auth.username || ''}" />
                </div>
                <div>
                  <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">\${tdict.password}</label>
                  <input id="inputPass" type="password" class="w-full px-3 py-2.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" value="\${auth.password || ''}" />
                </div>
              </div>
              <div class="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-lg text-xs text-blue-800 dark:text-blue-300 leading-relaxed border border-blue-100 dark:border-blue-800">\${tdict.corsTip}</div>
              <div class="flex space-x-3">
                <button id="btnDemo" class="flex-1 px-4 py-2.5 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 rounded-xl hover:bg-gray-50 dark:hover:bg-gray-700 font-medium">\${tdict.useDemo}</button>
                <button id="btnConnect" class="flex-1 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 dark:bg-blue-600 dark:hover:bg-blue-500 text-white rounded-xl font-medium shadow-md"> \${tdict.saveConnect} </button>
              </div>
            </div>
          </div>
        </div>
      \`;

      // attach events
      const searchInput = document.getElementById('searchInput');
      searchInput?.addEventListener('input', render);
      document.querySelectorAll('[data-view]').forEach(btn => {
        btn.addEventListener('click', () => { viewMode = btn.getAttribute('data-view'); render(); });
      });
      document.getElementById('openSettings')?.addEventListener('click', () => {
        document.getElementById('modal')?.classList.remove('hidden');
        document.getElementById('selectLang').value = lang;
        document.getElementById('selectTheme').value = theme;
      });
      document.getElementById('modalClose')?.addEventListener('click', () => document.getElementById('modal')?.classList.add('hidden'));
      document.getElementById('selectLang')?.addEventListener('change', (e) => { lang = e.target.value; localStorage.setItem('app_lang', lang); render(); });
      document.getElementById('selectTheme')?.addEventListener('change', (e) => { theme = e.target.value; localStorage.setItem('app_theme', theme); applyTheme(); });
      document.getElementById('breadcrumb-root')?.addEventListener('click', () => { currentPath = '/'; fetchFiles('/'); });
      document.querySelectorAll('[data-bc]').forEach(btn => btn.addEventListener('click', () => {
        const idx = parseInt(btn.getAttribute('data-bc'));
        const newPath = '/' + pathParts.slice(0, idx + 1).join('/') + '/';
        currentPath = newPath === '//' ? '/' : newPath;
        fetchFiles(currentPath);
      }));
      document.getElementById('btnRefresh')?.addEventListener('click', () => fetchFiles(currentPath));
      document.getElementById('btnMkcol')?.addEventListener('click', handleCreateFolder);
      document.getElementById('fileInput')?.addEventListener('change', (e) => {
        const f = e.target.files?.[0]; if (f) uploadFile(f);
      });
      document.getElementById('btnDemo')?.addEventListener('click', () => {
        isDemo = true; localStorage.removeItem('app_auth'); document.getElementById('modal')?.classList.add('hidden'); fetchFiles('/');
      });
      document.getElementById('btnConnect')?.addEventListener('click', () => {
        const url = document.getElementById('inputUrl').value.trim();
        const user = document.getElementById('inputUser').value.trim();
        const pass = document.getElementById('inputPass').value;
        if (!url) { alert('URL required'); return; }
        auth = { url, username: user, password: pass };
        localStorage.setItem('app_auth', JSON.stringify(auth));
        isDemo = false;
        currentPath = '/';
        document.getElementById('modal')?.classList.add('hidden');
        fetchFiles('/');
      });
      document.querySelectorAll('[data-href]').forEach(card => {
        card.addEventListener('click', () => {
          const href = card.getAttribute('data-href');
          const type = card.getAttribute('data-type');
          if (type === 'directory') {
            currentPath = href.endsWith('/') ? href : href + '/';
            fetchFiles(currentPath);
          } else {
            if (isDemo) {
              alert(t().demoMode + ': ' + href);
            } else {
              window.open(auth.url.replace(/\\/$/, '') + href, '_blank');
            }
          }
        });
      });
      document.querySelectorAll('[data-del]').forEach(btn => {
        btn.addEventListener('click', (e) => { e.stopPropagation(); const href = btn.getAttribute('data-del'); const file = files.find(f => f.href === href); if (file) handleDelete(file); });
      });
      document.querySelectorAll('[data-dl]').forEach(btn => {
        btn.addEventListener('click', (e) => { e.stopPropagation(); const href = btn.getAttribute('data-dl'); if (isDemo) alert(t().demoMode); else window.open(auth.url.replace(/\\/$/, '') + href, '_blank'); });
      });
    };

    // Drag & drop
    window.addEventListener('dragover', (e) => { e.preventDefault(); isDragging = true; render(); });
    window.addEventListener('dragleave', (e) => { e.preventDefault(); isDragging = false; render(); });
    window.addEventListener('drop', (e) => { e.preventDefault(); isDragging = false; const f = e.dataTransfer.files?.[0]; if (f) uploadFile(f); });

    // Initial render
    render();
    // Kick off first load (if not demo with initial data)
    fetchFiles(currentPath);
  </script>
</body>
</html>
`;
}

export function generateErrorHTML(title: string, message: string): string {
	return `
      <!DOCTYPE html>
      <html lang="en">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>${title}</title>
          <style>
              body {
                  font-family: Arial, sans-serif;
                  line-height: 1.6;
                  margin: 0;
                  padding: 20px;
                  background-color: #f4f4f4;
              }
              h1 {
                  color: #333;
              }
              .error-message {
                  background-color: white;
                  border-radius: 5px;
                  padding: 20px;
                  box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                  color: #e60000;
              }
          </style>
      </head>
      <body>
          <h1>${title}</h1>
          <div class="error-message">
              ${message}
          </div>
      </body>
      </html>
    `;
}
