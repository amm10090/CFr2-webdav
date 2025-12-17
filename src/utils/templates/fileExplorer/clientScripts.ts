import { TRANSLATIONS } from '../translations';

/**
 * Generate client-side JavaScript for file explorer
 * @param currentPath - Current directory path
 * @param initialItems - Initial file/folder items as JSON string
 * @returns JavaScript code as string
 */
export function generateFileExplorerScript(currentPath: string, initialItems: string): string {
	const translationsJSON = JSON.stringify(TRANSLATIONS);

	return `
    // ---- Translations ----
    const TRANSLATIONS = ${translationsJSON};

    // ---- State ----
    const app = document.getElementById('app');
    const initialPath = "${currentPath}";
    let currentPath = initialPath || "/";
    let files = ${initialItems};
    let searchTerm = "";
    let loading = false;
    let error = null;
    let viewMode = 'grid';
    let isDragging = false;
    let previewFile = null;
    let previewScale = 1;
    let previewRotation = 0;
    let previewKeyHandler = null;
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

    // ---- Upload Queue State ----
    let uploadQueue = [];
    let isUploading = false;

    // ---- Upload Configuration ----
    const UPLOAD_CONFIG = {
      maxFileSize: 100 * 1024 * 1024, // 100MB
      allowedExtensions: [
        'txt', 'md', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'rtf',
        'jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'bmp', 'ico', 'tiff', 'tif', 'heic', 'heif', 'avif',
        'mp3', 'wav', 'flac', 'aac', 'ogg', 'opus', 'm4a',
        'mp4', 'webm', 'mkv', 'avi', 'mov', 'flv', 'wmv', 'm4v',
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz',
        'json', 'xml', 'yml', 'yaml', 'csv', 'tsv',
        'js', 'ts', 'jsx', 'tsx', 'css', 'scss', 'html', 'vue', 'py', 'java', 'c', 'cpp', 'go', 'rs', 'php', 'rb', 'swift', 'kt'
      ]
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

    const isImageFile = (name) => {
      const ext = (name.split('.').pop() || '').toLowerCase();
      return ['jpg','jpeg','png','gif','svg','webp','bmp','ico','tiff','avif'].includes(ext);
    };

    const openPreview = (file) => {
      previewFile = file;
      previewScale = 1;
      previewRotation = 0;
      render();
    };

    const closePreview = () => {
      previewFile = null;
      render();
    };

    const applyLightboxTransform = () => {
      const img = document.getElementById('lightbox-image');
      if (img) {
        img.style.transform = 'scale(' + previewScale + ') rotate(' + previewRotation + 'deg)';
      }
    };

    const attachPreviewKeydown = () => {
      if (previewKeyHandler) {
        window.removeEventListener('keydown', previewKeyHandler);
      }
      if (!previewFile) {
        previewKeyHandler = null;
        return;
      }
      previewKeyHandler = (e) => {
        if (e.key === 'Escape') {
          closePreview();
        }
        if ((e.key === '+' || e.key === '=') && previewFile && isImageFile(previewFile.name)) {
          previewScale = Math.min(3, previewScale + 0.25);
          applyLightboxTransform();
        }
        if (e.key === '-' && previewFile && isImageFile(previewFile.name)) {
          previewScale = Math.max(0.5, previewScale - 0.25);
          applyLightboxTransform();
        }
      };
      window.addEventListener('keydown', previewKeyHandler);
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
    const refreshAccessToken = async () => {
      const session = JSON.parse(localStorage.getItem('app_session') || '{}');
      if (!session.refreshToken) return false;

      try {
        const res = await fetch('/auth/refresh', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refreshToken: session.refreshToken })
        });

        if (!res.ok) return false;

        const data = await res.json();
        session.accessToken = data.accessToken;
        session.expiresAt = Date.now() + (data.expiresIn || 900) * 1000;
        localStorage.setItem('app_session', JSON.stringify(session));
        return true;
      } catch (e) {
        console.error('Token refresh failed:', e);
        return false;
      }
    };

    const getHeaders = async () => {
      const headers = { Accept: 'application/xml, text/xml' };

      // Try JWT authentication first (from login page)
      const session = JSON.parse(localStorage.getItem('app_session') || '{}');
      if (session.accessToken) {
        // Check if token is expired or about to expire (within 1 minute)
        if (session.expiresAt && session.expiresAt - Date.now() < 60000) {
          const refreshed = await refreshAccessToken();
          if (!refreshed) {
            // Refresh failed, redirect to login
            localStorage.removeItem('app_session');
            window.location.href = '/login';
            return headers;
          }
          // Get updated session
          const updatedSession = JSON.parse(localStorage.getItem('app_session') || '{}');
          headers['Authorization'] = 'Bearer ' + updatedSession.accessToken;
        } else {
          headers['Authorization'] = 'Bearer ' + session.accessToken;
        }
        return headers;
      }

      // Fallback to Basic Auth (legacy)
      if (auth.username && auth.password) {
        headers['Authorization'] = 'Basic ' + btoa(auth.username + ':' + auth.password);
      }
      return headers;
    };

    const fetchFiles = async (path) => {
      loading = true; error = null; render();
      try {
        const url = auth.url.replace(/\\/$/, '') + path;
        const res = await fetch(url, { method: 'PROPFIND', headers: { ...(await getHeaders()), Depth: '1' } });
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
      } catch (e) {
        error = e.message || t().connectionError;
      } finally {
        loading = false;
        render();
      }
    };

    const handleDelete = async (file) => {
      if (!confirm(t().deleteConfirm.replace('{name}', file.name))) return;
      loading = true; render();
      try {
        const url = auth.url.replace(/\\/$/, '') + file.href;
        const res = await fetch(url, { method: 'DELETE', headers: await getHeaders() });
        if (!res.ok) throw new Error(t().deleteFailed);
        await fetchFiles(currentPath);
      } catch (e) {
        alert(e.message || t().deleteFailed);
        loading = false; render();
      }
    };

    const handleCreateFolder = async (name) => {
      if (!name) return;
      loading = true; render();
      try {
        const safePath = currentPath.endsWith('/') ? currentPath : currentPath + '/';
        const url = auth.url.replace(/\\/$/, '') + safePath + name;
        const res = await fetch(url, { method: 'MKCOL', headers: await getHeaders() });
        if (!res.ok) throw new Error(t().createFolderFailed);
        await fetchFiles(currentPath);
      } catch (e) {
        alert(e.message || t().createFolderFailed);
        loading = false; render();
      }
    };

    const uploadFile = async (file) => {
      // Deprecated: Use addFilesToQueue instead
      addFilesToQueue([file]);
    };

    // ---- Upload Queue Management ----
    const validateFile = (file) => {
      const ext = file.name.split('.').pop()?.toLowerCase() || '';

      if (!UPLOAD_CONFIG.allowedExtensions.includes(ext)) {
        return { valid: false, error: t().fileTypeNotAllowed };
      }

      if (file.size > UPLOAD_CONFIG.maxFileSize) {
        return { valid: false, error: t().fileTooLarge };
      }

      if (file.size === 0) {
        return { valid: false, error: t().fileEmpty };
      }

      return { valid: true };
    };

    const generatePreview = (item) => {
      if (item.size > 5 * 1024 * 1024) return; // Skip preview for files > 5MB

      const reader = new FileReader();
      reader.onload = (e) => {
        item.preview = e.target.result;
        render();
      };
      reader.readAsDataURL(item.file);
    };

    const addFilesToQueue = (files) => {
      const validFiles = [];
      const errors = [];

      for (const file of files) {
        const validation = validateFile(file);
        if (validation.valid) {
          validFiles.push({
            id: \`\${Date.now()}-\${Math.random().toString(36).slice(2, 9)}\`,
            file,
            name: file.name,
            size: file.size,
            status: 'pending',
            progress: 0,
            error: null,
            xhr: null,
            preview: null
          });
        } else {
          errors.push({ name: file.name, error: validation.error });
        }
      }

      uploadQueue.push(...validFiles);

      // Generate previews for images
      validFiles.forEach(item => {
        if (isImageFile(item.name)) {
          generatePreview(item);
        }
      });

      render();

      if (errors.length > 0) {
        const errorMsg = errors.map(e => \`\${e.name}: \${e.error}\`).join('\\n');
        alert(errorMsg);
      }

      // Auto-start upload
      if (!isUploading) {
        processUploadQueue();
      }
    };

    const processUploadQueue = async () => {
      if (isUploading) return;

      const nextItem = uploadQueue.find(item => item.status === 'pending');
      if (!nextItem) {
        isUploading = false;

        // Refresh file list if any uploads succeeded
        if (uploadQueue.some(i => i.status === 'completed')) {
          await fetchFiles(currentPath);
        }

        return;
      }

      isUploading = true;
      await uploadFileWithProgress(nextItem);

      // Continue with next file
      processUploadQueue();
    };

    const uploadFileWithProgress = async (item) => {
      return new Promise(async (resolve, reject) => {
        item.status = 'uploading';
        render();

        const safePath = currentPath.endsWith('/') ? currentPath : currentPath + '/';
        const url = auth.url.replace(/\\/$/, '') + safePath + item.file.name;

        const xhr = new XMLHttpRequest();
        item.xhr = xhr;

        // Progress tracking
        xhr.upload.addEventListener('progress', (e) => {
          if (e.lengthComputable) {
            item.progress = Math.round((e.loaded / e.total) * 100);
            render();
          }
        });

        // Success
        xhr.addEventListener('load', () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            item.status = 'completed';
            item.progress = 100;
            render();
            resolve();
          } else {
            item.status = 'error';
            item.error = t().uploadFailed;
            render();
            reject(new Error(xhr.statusText));
          }
        });

        // Error
        xhr.addEventListener('error', () => {
          item.status = 'error';
          item.error = t().uploadFailed;
          render();
          reject(new Error('Network error'));
        });

        // Abort (for pause/cancel)
        xhr.addEventListener('abort', () => {
          item.status = 'paused';
          render();
          resolve();
        });

        xhr.open('PUT', url);
        const headers = await getHeaders();
        Object.entries(headers).forEach(([key, value]) => {
          xhr.setRequestHeader(key, value);
        });
        xhr.send(item.file);
      });
    };

    const removeFromQueue = (id) => {
      const item = uploadQueue.find(i => i.id === id);
      if (item?.xhr && item.status === 'uploading') {
        item.xhr.abort();
      }
      uploadQueue = uploadQueue.filter(i => i.id !== id);
      render();
    };

    const clearCompletedUploads = () => {
      uploadQueue = uploadQueue.filter(i => i.status !== 'completed');
      render();
    };

    const clearAllUploads = () => {
      uploadQueue.forEach(item => {
        if (item.xhr && item.status === 'uploading') {
          item.xhr.abort();
        }
      });
      uploadQueue = [];
      isUploading = false;
      render();
    };

    const retryUpload = (id) => {
      const item = uploadQueue.find(i => i.id === id);
      if (item && item.status === 'error') {
        item.status = 'pending';
        item.error = null;
        item.progress = 0;
        render();
        if (!isUploading) {
          processUploadQueue();
        }
      }
    };

    // ---- UI ----
    const render = () => {
      const pathParts = currentPath.split('/').filter(Boolean);
      const filtered = files.filter((f) => f.name.toLowerCase().includes((document.getElementById('searchInput')?.value || '').toLowerCase()));
      const sorted = [...filtered].sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name) : a.type === 'directory' ? -1 : 1));
      const tdict = t();
      const previewIsImage = previewFile ? isImageFile(previewFile.name) : false;
      const previewSrc = previewFile
        ? (auth.url ? auth.url.replace(/\\/$/, '') + previewFile.href : previewFile.href)
        : '';
      applyTheme();

      // Extract username from JWT token
      const getUsername = () => {
        const session = JSON.parse(localStorage.getItem('app_session') || '{}');
        if (!session.accessToken) return '用户';

        try {
          const parts = session.accessToken.split('.');
          if (parts.length !== 3) return '用户';

          const payload = parts[1];
          const padding = '='.repeat((4 - (payload.length % 4)) % 4);
          const base64 = payload.replace(/-/g, '+').replace(/_/g, '/') + padding;
          const decoded = JSON.parse(atob(base64));

          return decoded.sub || '用户';
        } catch (e) {
          console.error('Failed to decode JWT:', e);
          return '用户';
        }
      };

      const username = getUsername();
      const userInitial = username.charAt(0).toUpperCase();

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
                  <span class="inline-block w-2 h-2 rounded-full \${'bg-green-500'}"></span>
                  <p class="text-xs text-gray-500 dark:text-gray-400 font-medium tracking-wide">\${(auth.url || '').replace(/^https?:\\/\\//,'')}</p>
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
              <div class="relative" id="avatarContainer">
                <button id="avatarBtn" class="relative flex items-center justify-center w-10 h-10 rounded-full text-white font-semibold text-sm hover:shadow-lg transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 dark:focus:ring-offset-gray-900" style="background: linear-gradient(to bottom right, rgb(59 130 246), rgb(147 51 234));">
                  <span id="avatarInitial">\${userInitial}</span>
                  <span id="2faIndicator" class="hidden absolute -top-0.5 -right-0.5 w-3.5 h-3.5 bg-green-500 border-2 border-white dark:border-gray-900 rounded-full"></span>
                </button>
                <div id="avatarDropdown" role="menu" aria-label="用户菜单" class="hidden absolute right-0 mt-2 w-64 bg-white dark:bg-gray-800 rounded-xl shadow-2xl border border-gray-200 dark:border-gray-700 overflow-hidden z-50" style="max-width: calc(100vw - 2rem);">
                  <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/50">
                    <p class="text-sm font-semibold text-gray-900 dark:text-white" id="dropdownUsername">\${username}</p>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5">已登录</p>
                  </div>
                  <div role="none" class="py-2">
                    <button id="menuTotp" role="menuitem" class="w-full px-4 py-2.5 text-left text-sm text-gray-700 dark:text-gray-200 hover:bg-blue-50 dark:hover:bg-gray-700 flex items-center space-x-3 transition">
                      <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                      <span>设置动态验证码</span>
                    </button>
                    <button id="menuPasskey" role="menuitem" class="w-full px-4 py-2.5 text-left text-sm text-gray-700 dark:text-gray-200 hover:bg-blue-50 dark:hover:bg-gray-700 flex items-center space-x-3 transition">
                      <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M15 7a2 2 0 0 1 2 2m4 0a6 6 0 0 1-7.743 5.743L11 17H9v2H7v2H4a1 1 0 0 1-1-1v-2.586a1 1 0 0 1 .293-.707l5.964-5.964A6 6 0 1 1 21 9z"/></svg>
                      <span>管理Passkey</span>
                    </button>
                    <button id="menuAccount" role="menuitem" class="w-full px-4 py-2.5 text-left text-sm text-gray-700 dark:text-gray-200 hover:bg-blue-50 dark:hover:bg-gray-700 flex items-center space-x-3 transition">
                      <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                      <span>账户设置</span>
                    </button>
                  </div>
                  <div role="none" class="border-t border-gray-200 dark:border-gray-700 py-2">
                    <button id="menuLogout" role="menuitem" class="w-full px-4 py-2.5 text-left text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 flex items-center space-x-3 transition">
                      <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>
                      <span>退出登录</span>
                    </button>
                  </div>
                </div>
              </div>
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
                <input id="fileInput" type="file" multiple class="hidden" />
              </label>
            </div>
          </div>
        </div>

        <div id="folderModal" role="dialog" aria-labelledby="folderModalTitle" class="fixed inset-0 z-50 hidden items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div class="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-sm w-full overflow-hidden border border-gray-100 dark:border-gray-700">
            <div class="px-5 py-3 border-b border-gray-100 dark:border-gray-700 flex justify-between items-center">
              <h3 id="folderModalTitle" class="text-lg font-semibold text-gray-900 dark:text-gray-100">\${tdict.newFolder}</h3>
              <button id="folderClose" aria-label="关闭" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 transition">&times;</button>
            </div>
            <div class="p-5 space-y-4">
              <input id="folderName" type="text" class="w-full px-3 py-2.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500" placeholder="\${tdict.newFolder}" />
              <div class="flex justify-end space-x-3">
                <button id="folderCancel" class="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700">\${tdict.cancel || '取消'}</button>
                <button id="folderConfirm" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg shadow-sm">\${tdict.save || '确定'}</button>
              </div>
            </div>
          </div>
        </div>

        <div id="totpModal" role="dialog" aria-labelledby="totpModalTitle" class="fixed inset-0 z-50 hidden items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div class="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-lg w-full overflow-hidden border border-gray-100 dark:border-gray-700">
            <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center">
              <h3 id="totpModalTitle" class="text-lg font-semibold text-gray-900 dark:text-gray-100">动态验证码设置</h3>
              <button id="totpModalClose" aria-label="关闭" class="text-2xl text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 transition leading-none">&times;</button>
            </div>
            <div id="totpModalContent" class="p-6 space-y-4 max-h-[65vh] overflow-y-auto">
              <div class="text-center"><p class="text-sm text-gray-600 dark:text-gray-400">正在加载...</p></div>
            </div>
          </div>
        </div>

        <div id="passkeyModal" role="dialog" aria-labelledby="passkeyModalTitle" class="fixed inset-0 z-50 hidden items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div class="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-lg w-full overflow-hidden border border-gray-100 dark:border-gray-700">
            <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center">
              <h3 id="passkeyModalTitle" class="text-lg font-semibold text-gray-900 dark:text-gray-100">Passkey管理</h3>
              <button id="passkeyModalClose" aria-label="关闭" class="text-2xl text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 transition leading-none">&times;</button>
            </div>
            <div id="passkeyModalContent" class="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
              <div class="text-center"><p class="text-sm text-gray-600 dark:text-gray-400">正在加载...</p></div>
            </div>
          </div>
        </div>

        <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
          \${uploadQueue.length > 0 ? \`
            <div class="fixed bottom-4 right-4 w-96 max-w-[calc(100vw-2rem)] bg-white dark:bg-gray-800 rounded-xl shadow-2xl border border-gray-200 dark:border-gray-700 overflow-hidden z-40">
              <div class="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between bg-gradient-to-r from-blue-50 to-white dark:from-gray-800 dark:to-gray-800">
                <div class="flex items-center space-x-2">
                  <svg class="text-blue-600 dark:text-blue-400" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 17v2h16v-2M12 12v9m-5-9 5-5 5 5"/></svg>
                  <h3 class="text-sm font-semibold text-gray-900 dark:text-white">\${tdict.uploadQueue}</h3>
                  <span class="text-xs text-gray-500 dark:text-gray-400">(\${uploadQueue.length})</span>
                </div>
                <button id="queueClearCompleted" class="text-xs text-gray-500 hover:text-red-600 dark:text-gray-400 dark:hover:text-red-400 font-medium">
                  \${tdict.clearCompleted}
                </button>
              </div>
              <div class="max-h-96 overflow-y-auto">
                \${uploadQueue.map(item => \`
                  <div class="px-4 py-3 border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750 transition">
                    <div class="flex items-start space-x-3">
                      <div class="flex-shrink-0 w-10 h-10 rounded-lg overflow-hidden bg-gray-100 dark:bg-gray-700 flex items-center justify-center">
                        \${item.preview ? \`
                          <img src="\${item.preview}" alt="\${item.name}" class="w-full h-full object-cover" />
                        \` : \`
                          \${renderFileIcon({ name: item.name, type: 'file' }, 24)}
                        \`}
                      </div>
                      <div class="flex-1 min-w-0">
                        <div class="flex items-center justify-between mb-1">
                          <p class="text-sm font-medium text-gray-900 dark:text-white truncate pr-2">\${item.name}</p>
                          <button data-remove-upload="\${item.id}" class="flex-shrink-0 text-gray-400 hover:text-red-500 dark:hover:text-red-400">
                            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                          </button>
                        </div>
                        <p class="text-xs text-gray-500 dark:text-gray-400 mb-2">\${formatBytes(item.size)}</p>
                        \${item.status === 'uploading' || item.status === 'completed' ? \`
                          <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5 mb-1">
                            <div class="bg-blue-600 dark:bg-blue-500 h-1.5 rounded-full transition-all duration-300" style="width: \${item.progress}%"></div>
                          </div>
                        \` : ''}
                        <div class="flex items-center justify-between">
                          \${item.status === 'pending' ? \`
                            <span class="text-xs text-gray-500 dark:text-gray-400">\${tdict.pending}</span>
                          \` : item.status === 'uploading' ? \`
                            <span class="text-xs text-blue-600 dark:text-blue-400 font-medium">\${tdict.uploading} \${item.progress}%</span>
                          \` : item.status === 'completed' ? \`
                            <span class="inline-flex items-center text-xs text-green-600 dark:text-green-400 font-medium">
                              <svg class="mr-1" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>
                              \${tdict.completed}
                            </span>
                          \` : item.status === 'error' ? \`
                            <div class="flex items-center space-x-2">
                              <span class="text-xs text-red-600 dark:text-red-400">\${item.error || tdict.uploadFailed}</span>
                              <button data-retry-upload="\${item.id}" class="text-xs text-blue-600 hover:text-blue-700 dark:text-blue-400 font-medium">
                                \${tdict.retryUpload}
                              </button>
                            </div>
                          \` : ''}
                        </div>
                      </div>
                    </div>
                  </div>
                \`).join('')}
              </div>
              <div class="px-4 py-3 bg-gray-50 dark:bg-gray-900/50 border-t border-gray-200 dark:border-gray-700">
                <div class="flex items-center justify-between text-xs">
                  <span class="text-gray-600 dark:text-gray-400">
                    \${tdict.selectedFiles.replace('{count}', uploadQueue.length).replace('{size}', formatBytes(uploadQueue.reduce((sum, item) => sum + item.size, 0)))}
                  </span>
                </div>
              </div>
            </div>
          \` : ''}

          \${error ? \`
            <div class="mb-6 bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 p-4 rounded-r-lg flex items-start animate-fade-in">
              <svg class="text-red-500 dark:text-red-400 mt-0.5 mr-3" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
              <div>
                <h3 class="text-sm font-medium text-red-800 dark:text-red-200">\${tdict.connectionError}</h3>
                <p class="text-sm text-red-700 dark:text-red-300 mt-1">\${error}</p>
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
                <div data-href="\${file.href}" data-type="\${file.type}" data-name="\${file.name}"
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
                    <tr data-href="\${file.href}" data-type="\${file.type}" data-name="\${file.name}" class="hover:bg-blue-50/50 dark:hover:bg-blue-900/10 cursor-pointer transition group">
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
          <div class="fixed inset-0 z-50 pointer-events-none flex items-center justify-center">
            <div class="absolute inset-0 bg-blue-500/10 backdrop-blur-sm border-4 border-blue-500 border-dashed m-4 rounded-2xl"></div>
            <div class="relative bg-white dark:bg-gray-800 p-6 rounded-xl shadow-xl flex flex-col items-center animate-bounce border border-gray-200 dark:border-gray-700">
              <svg class="text-blue-600 dark:text-blue-400 mb-2" width="48" height="48" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 17v2h16v-2M12 12v9m-5-9 5-5 5 5"/></svg>
              <span class="text-xl font-bold text-blue-800 dark:text-blue-300">\${tdict.dropToUpload}</span>
            </div>
          </div>\` : ''}

        \${previewFile ? \`
          <div id="lightbox" class="fixed inset-0 z-[55] bg-black/80 backdrop-blur-sm flex flex-col items-center justify-center p-4 text-white">
            <div class="absolute top-4 right-4 flex items-center gap-2">
              <button id="lb-zoom-out" class="p-2 rounded-full bg-white/10 hover:bg-white/20 border border-white/10" title="缩小">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"/></svg>
              </button>
              <button id="lb-zoom-in" class="p-2 rounded-full bg-white/10 hover:bg-white/20 border border-white/10" title="放大">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
              </button>
              <button id="lb-rotate" class="p-2 rounded-full bg-white/10 hover:bg-white/20 border border-white/10" title="旋转90°">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 4 10 4 10 10"/><polyline points="20 20 14 20 14 14"/><line x1="14" y1="10" x2="20" y2="4"/><line x1="10" y1="14" x2="4" y2="20"/></svg>
              </button>
              <button id="lb-close" class="p-2 rounded-full bg-white/10 hover:bg-red-500/70 border border-white/10" title="关闭">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              </button>
            </div>
            <div class="max-w-6xl w-full flex items-center justify-center max-h-[85vh]">
              \${previewIsImage ? \`
                <img id="lightbox-image" src="\${previewSrc}" alt="\${previewFile?.name || ''}"
                  class="max-h-[80vh] max-w-full object-contain shadow-2xl rounded-xl border border-white/10 bg-white/5"
                  style="transform: scale(\${previewScale}) rotate(\${previewRotation}deg); transition: transform 120ms ease-out;" />
              \` : \`
                <div class="text-center space-y-3">
                  <p class="text-lg font-semibold">当前仅支持图片预览</p>
                  <button id="lb-close2" class="px-4 py-2 bg-white/20 rounded-lg hover:bg-white/30">关闭</button>
                </div>
              \`}
            </div>
            <div class="mt-3 text-sm text-white/70 truncate max-w-3xl px-3">\${previewFile?.name || ''}</div>
          </div>\`
        : ''}

        <div id="modal" role="dialog" aria-labelledby="modalTitle" class="fixed inset-0 z-50 hidden items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div class="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl max-w-md w-full overflow-hidden border border-gray-100 dark:border-gray-700">
            <div class="px-6 py-4 bg-gradient-to-r from-gray-50 to-white dark:from-gray-800 dark:to-gray-800 border-b border-gray-100 dark:border-gray-700 flex justify-between items-center">
              <div class="flex items-center space-x-2">
                <svg class="text-gray-500 dark:text-gray-400" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.09a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/></svg>
                <h3 id="modalTitle" class="text-lg font-semibold text-gray-900 dark:text-gray-100">\${tdict.settingsTitle}</h3>
              </div>
              <button id="modalClose" aria-label="关闭" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 transition">&times;</button>
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
                <button id="btnConnect" class="flex-1 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 dark:bg-blue-600 dark:hover:bg-blue-500 text-white rounded-xl font-medium shadow-md"> \${tdict.saveConnect} </button>
              </div>
              <div class="pt-2 border-t border-gray-200 dark:border-gray-700">
                <button id="btnLogout" class="w-full px-4 py-2.5 border border-red-300 dark:border-red-600 text-red-600 dark:text-red-400 rounded-xl hover:bg-red-50 dark:hover:bg-red-900/20 font-medium transition-colors">
                  <svg class="inline-block w-4 h-4 mr-1.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>
                  </svg>
                  \${tdict.logout}
                </button>
              </div>
            </div>
          </div>
        </div>
      \`;

      // 模态框管理器
      const modalStack = [];
      const focusableSelectors = 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

      const openModal = (modalId, triggerElement) => {
        const modal = document.getElementById(modalId);
        if (!modal) return;

        modal.classList.remove('hidden');
        modal.classList.add('flex');
        modal.setAttribute('aria-modal', 'true');
        document.body.style.overflow = 'hidden';

        modalStack.push({ id: modalId, trigger: triggerElement });

        setTimeout(() => {
          const focusable = modal.querySelectorAll(focusableSelectors);
          if (focusable.length) focusable[0].focus();
        }, 50);
      };

      const closeModal = (modalId) => {
        const modal = document.getElementById(modalId);
        if (!modal) return;

        modal.classList.add('hidden');
        modal.classList.remove('flex');
        modal.removeAttribute('aria-modal');

        const idx = modalStack.findIndex(m => m.id === modalId);
        if (idx >= 0) {
          const { trigger } = modalStack.splice(idx, 1)[0];
          if (modalStack.length === 0) {
            document.body.style.overflow = '';
          }
          if (trigger && trigger.focus) trigger.focus();
        }
      };

      // 全局ESC和焦点陷阱
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && modalStack.length > 0) {
          const { id } = modalStack[modalStack.length - 1];
          closeModal(id);
          return;
        }

        if (e.key === 'Tab' && modalStack.length > 0) {
          const { id } = modalStack[modalStack.length - 1];
          const modal = document.getElementById(id);
          if (!modal) return;

          const focusable = Array.from(modal.querySelectorAll(focusableSelectors));
          if (focusable.length === 0) return;

          const activeEl = document.activeElement;
          const activeIdx = focusable.indexOf(activeEl);

          if (e.shiftKey) {
            if (activeIdx <= 0) {
              e.preventDefault();
              focusable[focusable.length - 1].focus();
            }
          } else {
            if (activeIdx >= focusable.length - 1) {
              e.preventDefault();
              focusable[0].focus();
            }
          }
        }
      });

      // attach events
      const searchInput = document.getElementById('searchInput');
      searchInput?.addEventListener('input', (e) => {
        const el = e.target;
        const pos = el.selectionStart || el.value.length;
        searchTerm = el.value;
        render();
        const again = document.getElementById('searchInput');
        if (again) {
          again.focus();
          again.setSelectionRange(pos, pos);
        }
      });
      document.querySelectorAll('[data-view]').forEach(btn => {
        btn.addEventListener('click', () => { viewMode = btn.getAttribute('data-view'); render(); });
      });
      document.getElementById('openSettings')?.addEventListener('click', (e) => {
        openModal('modal', e.target);
        document.getElementById('selectLang').value = lang;
        document.getElementById('selectTheme').value = theme;
      });

      // Check 2FA status and update indicator
      const check2FAStatus = async () => {
        try {
          const res = await fetch('/auth/2fa/status', { headers: await getHeaders() });
          if (res.ok) {
            const data = await res.json();
            const indicator = document.getElementById('2faIndicator');
            if (indicator) {
              indicator.classList.toggle('hidden', !data.enabled);
            }
          }
        } catch (e) {
          console.error('Failed to check 2FA status:', e);
        }
      };

      // Call check2FAStatus after a short delay to allow DOM to settle
      setTimeout(check2FAStatus, 100);

      // 头像下拉菜单：支持键盘导航，并在窄视口/缩放时避免右侧溢出屏幕
      let dropdownOpen = false;
      let dropdownFocusIdx = -1;

      const getViewportWidth = () => {
        const vv = window.visualViewport;
        return vv?.width || document.documentElement.clientWidth || window.innerWidth;
      };

      const repositionAvatarDropdown = (dropdown) => {
        if (!dropdown || dropdown.classList.contains('hidden')) return;
        dropdown.style.transform = '';

        // 预留一点边距，避免阴影被裁切/贴边导致“溢出”观感
        const viewportPadding = 24;
        const viewportWidth = getViewportWidth();
        const rect = dropdown.getBoundingClientRect();

        let translateX = 0;
        if (rect.right > viewportWidth - viewportPadding) {
          translateX -= rect.right - (viewportWidth - viewportPadding);
        }
        if (rect.left < viewportPadding) {
          translateX += viewportPadding - rect.left;
        }
        if (translateX !== 0) {
          dropdown.style.transform = \`translateX(\${translateX}px)\`;
        }
      };

      const closeDropdown = () => {
        const dropdown = document.getElementById('avatarDropdown');
        if (dropdown) dropdown.style.transform = '';
        dropdown?.classList.add('hidden');
        dropdownOpen = false;
        dropdownFocusIdx = -1;
      };

      document.getElementById('avatarBtn')?.addEventListener('click', (e) => {
        e.stopPropagation();
        const dropdown = document.getElementById('avatarDropdown');

        if (dropdown) {
          const wasHidden = dropdown.classList.contains('hidden');
          dropdown.classList.toggle('hidden');
          dropdownOpen = !wasHidden;

          if (dropdownOpen) {
            requestAnimationFrame(() => {
              repositionAvatarDropdown(dropdown);
              const buttons = dropdown.querySelectorAll('button[role="menuitem"]');
              if (buttons.length) {
                dropdownFocusIdx = 0;
                buttons[0].focus();
              }
            });
          } else {
            dropdownFocusIdx = -1;
          }
        }
      });

      const handleAvatarDropdownViewportChange = () => {
        if (!dropdownOpen) return;
        const dropdown = document.getElementById('avatarDropdown');
        if (dropdown) repositionAvatarDropdown(dropdown);
      };
      window.addEventListener('resize', handleAvatarDropdownViewportChange);
      window.visualViewport?.addEventListener('resize', handleAvatarDropdownViewportChange);
      window.visualViewport?.addEventListener('scroll', handleAvatarDropdownViewportChange);

      // Keyboard navigation for dropdown
      document.addEventListener('keydown', (e) => {
        if (!dropdownOpen) return;
        const dropdown = document.getElementById('avatarDropdown');
        if (!dropdown) return;
        const buttons = Array.from(dropdown.querySelectorAll('button[role="menuitem"]'));

        if (e.key === 'ArrowDown') {
          e.preventDefault();
          dropdownFocusIdx = Math.min(dropdownFocusIdx + 1, buttons.length - 1);
          buttons[dropdownFocusIdx]?.focus();
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          dropdownFocusIdx = Math.max(dropdownFocusIdx - 1, 0);
          buttons[dropdownFocusIdx]?.focus();
        } else if (e.key === 'Escape') {
          e.preventDefault();
          closeDropdown();
          document.getElementById('avatarBtn')?.focus();
        }
      });

      // Close dropdown when clicking outside
      document.addEventListener('click', (e) => {
        const container = document.getElementById('avatarContainer');
        if (container && !container.contains(e.target)) {
          closeDropdown();
        }
      });

      // Menu item: TOTP
      document.getElementById('menuTotp')?.addEventListener('click', () => {
        closeDropdown();
        openTotpModal();
      });

      // Menu item: Passkey
      document.getElementById('menuPasskey')?.addEventListener('click', () => {
        closeDropdown();
        openPasskeyModal();
      });

      // Menu item: Account Settings
      document.getElementById('menuAccount')?.addEventListener('click', (e) => {
        closeDropdown();
        openModal('modal', e.target);
        document.getElementById('selectLang').value = lang;
        document.getElementById('selectTheme').value = theme;
      });

      // Menu item: Logout
      document.getElementById('menuLogout')?.addEventListener('click', () => {
        document.getElementById('avatarDropdown')?.classList.add('hidden');
        if (confirm('确定要退出登录吗？')) {
          localStorage.removeItem('app_session');
          localStorage.removeItem('app_auth');
          window.location.href = '/login';
        }
      });

      document.getElementById('modalClose')?.addEventListener('click', () => {
        closeModal('modal');
      });
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
      const folderModal = document.getElementById('folderModal');
      const folderNameInput = document.getElementById('folderName');

      document.getElementById('btnMkcol')?.addEventListener('click', (e) => {
        openModal('folderModal', e.target);
      });
      document.getElementById('folderClose')?.addEventListener('click', () => {
        closeModal('folderModal');
      });
      document.getElementById('folderCancel')?.addEventListener('click', () => {
        closeModal('folderModal');
      });
      document.getElementById('folderConfirm')?.addEventListener('click', () => {
        const input = document.getElementById('folderName');
        const name = input ? input.value.trim() : '';
        closeModal('folderModal');
        if (input) input.value = '';
        if (name) handleCreateFolder(name);
      });
      document.getElementById('fileInput')?.addEventListener('change', (e) => {
        const files = Array.from(e.target.files || []);
        if (files.length > 0) {
          addFilesToQueue(files);
          e.target.value = ''; // Reset input to allow re-selecting same files
        }
      });
      document.getElementById('queueClearCompleted')?.addEventListener('click', clearCompletedUploads);
      document.querySelectorAll('[data-remove-upload]').forEach(btn => {
        btn.addEventListener('click', () => removeFromQueue(btn.getAttribute('data-remove-upload')));
      });
      document.querySelectorAll('[data-retry-upload]').forEach(btn => {
        btn.addEventListener('click', () => retryUpload(btn.getAttribute('data-retry-upload')));
      });
      document.getElementById('btnConnect')?.addEventListener('click', () => {
        const url = document.getElementById('inputUrl').value.trim();
        const user = document.getElementById('inputUser').value.trim();
        const pass = document.getElementById('inputPass').value;
        if (!url) { alert('URL required'); return; }
        auth = { url, username: user, password: pass };
        localStorage.setItem('app_auth', JSON.stringify(auth));
        currentPath = '/';
        document.getElementById('modal')?.classList.add('hidden');
        document.getElementById('modal')?.classList.remove('flex');
        fetchFiles('/');
      });
      document.getElementById('btnLogout')?.addEventListener('click', () => {
        if (confirm(t().logoutConfirm)) {
          // Clear all authentication data
          localStorage.removeItem('app_session');
          localStorage.removeItem('app_auth');
          // Redirect to login page
          window.location.href = '/login';
        }
      });
      document.querySelectorAll('[data-href]').forEach(card => {
        card.addEventListener('click', () => {
          const href = card.getAttribute('data-href');
          const type = card.getAttribute('data-type');
          const name = card.getAttribute('data-name') || '';
          const file = files.find((f) => f.href === href) || { name, href, type };
          if (type === 'directory') {
            currentPath = href.endsWith('/') ? href : href + '/';
            fetchFiles(currentPath);
          } else if (isImageFile(file.name)) {
            openPreview(file);
          } else {
            window.open(auth.url.replace(/\\/$/, '') + href, '_blank');
          }
        });
      });
      document.querySelectorAll('[data-del]').forEach(btn => {
        btn.addEventListener('click', (e) => { e.stopPropagation(); const href = btn.getAttribute('data-del'); const file = files.find(f => f.href === href); if (file) handleDelete(file); });
      });
      document.querySelectorAll('[data-dl]').forEach(btn => {
        btn.addEventListener('click', (e) => { e.stopPropagation(); const href = btn.getAttribute('data-dl'); window.open(auth.url.replace(/\\/$/, '') + href, '_blank'); });
      });
      const lb = document.getElementById('lightbox');
      if (lb) {
        lb.addEventListener('click', (e) => { if (e.target === lb) closePreview(); });
      }
      const bindLb = (id, fn) => {
        const el = document.getElementById(id);
        if (el) {
          el.addEventListener('click', (e) => { e.stopPropagation(); fn(); });
        }
      };
      bindLb('lb-close', closePreview);
      bindLb('lb-close2', closePreview);
      bindLb('lb-zoom-in', () => { previewScale = Math.min(3, previewScale + 0.25); applyLightboxTransform(); });
      bindLb('lb-zoom-out', () => { previewScale = Math.max(0.5, previewScale - 0.25); applyLightboxTransform(); });
      bindLb('lb-rotate', () => { previewRotation = (previewRotation + 90) % 360; applyLightboxTransform(); });
      applyLightboxTransform();
      attachPreviewKeydown();

      // TOTP Modal close
      document.getElementById('totpModalClose')?.addEventListener('click', () => {
        closeModal('totpModal');
      });

      // Passkey Modal close
      document.getElementById('passkeyModalClose')?.addEventListener('click', () => {
        closeModal('passkeyModal');
      });
    };

    // TOTP Modal Functions
    const openTotpModal = async () => {
      const content = document.getElementById('totpModalContent');
      openModal('totpModal', document.getElementById('menuTotp'));

      try {
        const res = await fetch('/auth/2fa/status', { headers: await getHeaders() });
        const data = await res.json();

        if (data.enabled) {
          content.innerHTML = \`
            <div class="text-center space-y-4">
              <div class="w-16 h-16 mx-auto bg-green-100 dark:bg-green-900/30 rounded-full flex items-center justify-center">
                <svg class="w-8 h-8 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M5 13l4 4L19 7"/></svg>
              </div>
              <p class="text-sm text-gray-600 dark:text-gray-400">动态验证码已启用</p>
              <div class="space-y-2">
                <button id="btnResetTotp" class="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg">重置动态验证码</button>
                <button id="btnDisableTotp" class="w-full px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg">禁用动态验证码</button>
              </div>
              <p class="text-xs text-gray-500 dark:text-gray-500">重置会生成新的密钥和恢复码，需要重新在认证器中添加。</p>
            </div>
          \`;

          document.getElementById('btnResetTotp')?.addEventListener('click', resetTotp);
          document.getElementById('btnDisableTotp')?.addEventListener('click', disableTotp);
        } else {
          content.innerHTML = '<div class="text-center"><p class="text-sm text-gray-600 dark:text-gray-400 mb-4">正在初始化...</p></div>';
          await setupTotp();
        }
      } catch (e) {
        content.innerHTML = \`<p class="text-red-600">加载失败: \${e.message}</p>\`;
      }
    };

    const resetTotp = async () => {
      if (!confirm('确定要重置动态验证码吗？这会生成新的密钥和恢复码，需要重新绑定认证器。')) return;

      const password = prompt('请输入密码以重置动态验证码:');
      if (!password) return;

      const content = document.getElementById('totpModalContent');
      content.innerHTML = '<div class="text-center"><p class="text-sm text-gray-600 dark:text-gray-400 mb-4">正在重置...</p></div>';

      try {
        const res = await fetch('/auth/2fa/disable', {
          method: 'POST',
          headers: { ...(await getHeaders()), 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });

        const payload = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(payload.error || '重置失败');

        setTimeout(check2FAStatus, 100);
        await setupTotp();
      } catch (e) {
        content.innerHTML = \`<p class="text-red-600">重置失败: \${e.message}</p>\`;
      }
    };

    const setupTotp = async () => {
      const content = document.getElementById('totpModalContent');

      try {
        const res = await fetch('/auth/2fa/setup', {
          method: 'POST',
          headers: await getHeaders()
        });

        if (!res.ok) throw new Error('初始化失败');

        const data = await res.json();

        const qrImgSrc = data.qrCodeUri.startsWith('data:image')
          ? data.qrCodeUri
          : \`https://api.qrserver.com/v1/create-qr-code/?size=160x160&data=\${encodeURIComponent(data.qrCodeUri)}\`;

        content.innerHTML = \`
          <div class="space-y-3">
            <div class="text-center">
              <p class="text-sm text-gray-600 dark:text-gray-400 mb-2">使用认证器应用扫描二维码</p>
              <div class="inline-block p-3 bg-white rounded-lg">
                <img src="\${qrImgSrc}" alt="QR Code" class="w-40 h-40" />
              </div>
              <p class="text-xs text-gray-500 mt-2">
                或手动输入密钥: <code class="bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">\${data.secret}</code>
              </p>
            </div>

            <div class="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-3">
              <p class="text-sm font-semibold text-yellow-800 dark:text-yellow-200 mb-2">恢复码（请妥善保存）</p>
              <div class="grid grid-cols-2 gap-1.5 text-xs font-mono">
                \${data.recoveryCodes.map(code => \`<div class="bg-white dark:bg-gray-800 px-2 py-1 rounded">\${code}</div>\`).join('')}
              </div>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">输入验证码确认</label>
              <input id="totpVerifyCode" type="text" maxlength="6" pattern="[0-9]{6}" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-center text-lg tracking-widest" placeholder="000000" />
            </div>

            <button id="btnVerifyTotp" class="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg">确认启用</button>
          </div>
        \`;

        document.getElementById('btnVerifyTotp')?.addEventListener('click', async () => {
          const code = document.getElementById('totpVerifyCode').value;
          if (!/^\\d{6}$/.test(code)) {
            alert('请输入6位数字验证码');
            return;
          }

          try {
            const verifyRes = await fetch('/auth/2fa/verify-setup', {
              method: 'POST',
              headers: { ...(await getHeaders()), 'Content-Type': 'application/json' },
              body: JSON.stringify({ code })
            });

            if (!verifyRes.ok) throw new Error('验证失败');

            alert('动态验证码已成功启用！');
            document.getElementById('totpModal')?.classList.add('hidden');
            document.getElementById('totpModal')?.classList.remove('flex');
            setTimeout(check2FAStatus, 100);
          } catch (e) {
            alert('验证失败: ' + e.message);
          }
        });
      } catch (e) {
        content.innerHTML = \`<p class="text-red-600">设置失败: \${e.message}</p>\`;
      }
    };

    const disableTotp = async () => {
      const password = prompt('请输入密码以禁用动态验证码:');
      if (!password) return;

      try {
        const res = await fetch('/auth/2fa/disable', {
          method: 'POST',
          headers: { ...(await getHeaders()), 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });

        if (!res.ok) throw new Error('禁用失败');

        alert('动态验证码已禁用');
        document.getElementById('totpModal')?.classList.add('hidden');
        document.getElementById('totpModal')?.classList.remove('flex');
        setTimeout(check2FAStatus, 100);
      } catch (e) {
        alert('禁用失败: ' + e.message);
      }
    };

    // Passkey Modal Functions
    const openPasskeyModal = async () => {
      openModal('passkeyModal', document.getElementById('menuPasskey'));
      await loadPasskeys();
    };

    const loadPasskeys = async () => {
      const content = document.getElementById('passkeyModalContent');

      try {
        const res = await fetch('/auth/passkeys', { headers: await getHeaders() });
        const data = await res.json();

        content.innerHTML = \`
          <div class="space-y-4">
            <button id="btnAddPasskey" class="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center justify-center space-x-2">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
              <span>添加新Passkey</span>
            </button>

            \${data.passkeys.length === 0 ? \`
              <div class="text-center py-8 text-gray-500 dark:text-gray-400">
                <p class="text-sm">暂无Passkey</p>
              </div>
            \` : \`
              <div class="space-y-2">
                \${data.passkeys.map(pk => \`
                  <div class="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                    <div class="flex-1">
                      <p class="text-sm font-medium text-gray-900 dark:text-white">\${pk.name}</p>
                      <p class="text-xs text-gray-500 dark:text-gray-400">\${new Date(pk.createdAt).toLocaleDateString()}</p>
                    </div>
                    <button data-passkey-id="\${pk.id}" class="btn-delete-passkey p-2 text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg">
                      <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                    </button>
                  </div>
                \`).join('')}
              </div>
            \`}
          </div>
        \`;

        document.getElementById('btnAddPasskey')?.addEventListener('click', registerPasskey);
        document.querySelectorAll('.btn-delete-passkey').forEach(btn => {
          btn.addEventListener('click', async (e) => {
            const id = e.currentTarget.getAttribute('data-passkey-id');
            if (confirm('确定删除此Passkey？')) {
              await deletePasskey(id);
            }
          });
        });
      } catch (e) {
        content.innerHTML = \`<p class="text-red-600">加载失败: \${e.message}</p>\`;
      }
    };

    const registerPasskey = async () => {
      try {
        const startRes = await fetch('/auth/passkey/register/start', {
          method: 'POST',
          headers: await getHeaders()
        });
        const { options, challengeId } = await startRes.json();

        const credential = await navigator.credentials.create({
          publicKey: {
            ...options,
            challenge: Uint8Array.from(atob(options.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
            user: {
              ...options.user,
              id: Uint8Array.from(atob(options.user.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
            }
          }
        });

        const finishRes = await fetch('/auth/passkey/register/finish', {
          method: 'POST',
          headers: { ...(await getHeaders()), 'Content-Type': 'application/json' },
          body: JSON.stringify({
            credential: serializeCredential(credential),
            challengeId,
            name: prompt('为此Passkey命名:') || \`Passkey \${new Date().toLocaleDateString()}\`
          })
        });

        if (!finishRes.ok) throw new Error('注册失败');

        alert('Passkey注册成功！');
        await loadPasskeys();
      } catch (e) {
        alert('注册失败: ' + e.message);
      }
    };

    const deletePasskey = async (id) => {
      try {
        const res = await fetch(\`/auth/passkey/\${id}\`, {
          method: 'DELETE',
          headers: await getHeaders()
        });

        if (!res.ok) throw new Error('删除失败');

        await loadPasskeys();
      } catch (e) {
        alert('删除失败: ' + e.message);
      }
    };

    const serializeCredential = (credential) => {
      const arrayBufferToBase64url = (buffer) => {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).split('+').join('-').split('/').join('_').split('=').join('');
      };

      return {
        id: credential.id,
        rawId: arrayBufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
          attestationObject: arrayBufferToBase64url(credential.response.attestationObject)
        }
      };
    };

    // Drag & drop
    window.addEventListener('dragenter', (e) => {
      console.log('dragenter', e.target);
      e.preventDefault();
      isDragging = true;
      render();
    });
    window.addEventListener('dragover', (e) => {
      e.preventDefault();
    });
    window.addEventListener('dragleave', (e) => {
      console.log('dragleave', e.target, e.clientX, e.clientY);
      e.preventDefault();
      if (e.clientX === 0 && e.clientY === 0) {
        isDragging = false;
        render();
      }
    });
    window.addEventListener('drop', (e) => {
      console.log('drop triggered', e.dataTransfer.files);
      e.preventDefault();
      isDragging = false;
      const files = Array.from(e.dataTransfer.files || []);
      if (files.length > 0) {
        addFilesToQueue(files);
      }
      render();
    });

    // Prevent page close during upload
    window.addEventListener('beforeunload', (e) => {
      if (uploadQueue.some(i => i.status === 'uploading')) {
        e.preventDefault();
        e.returnValue = '';
        return t().uploadInProgress;
      }
    });

    // Initial render
    render();

    // Check authentication before loading data
    const session = JSON.parse(localStorage.getItem('app_session') || '{}');
    const hasJWT = session.accessToken;
    const hasBasicAuth = auth.username && auth.password;

    if (!hasJWT && !hasBasicAuth) {
      // No authentication found, redirect to login
      window.location.href = '/login';
    } else {
      // Authenticated - load files
      fetchFiles(currentPath);
    }
  </script>
  `;
}
