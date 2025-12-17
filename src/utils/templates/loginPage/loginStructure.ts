import { LOGO_DATA_URL } from '../constants';

/**
 * Generate HTML body structure for login page
 * @returns HTML body content as string
 */
export function generateLoginHTMLBody(): string {
	return `
<body class="bg-gray-100 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
  <div class="min-h-screen flex items-center justify-center p-6 relative overflow-hidden">
    <!-- Organic background blobs -->
    <div class="blob-container">
      <div class="organic-blob blob-1"></div>
      <div class="organic-blob blob-2"></div>
      <div class="organic-blob blob-3"></div>
    </div>

    <div class="max-w-md w-full animate-fade-in relative z-10">
      <!-- Card Container -->
      <div class="bg-white dark:bg-gray-800 rounded-2xl shadow-md p-8 border border-gray-200 dark:border-gray-700 login-card">
        <!-- Logo & Brand -->
        <div class="flex flex-col items-center mb-8">
          <div class="mb-3">
            <img src="${LOGO_DATA_URL}" alt="Logo" width="64" height="64" style="object-fit: contain;" />
          </div>
          <h2 class="text-lg font-semibold text-gray-900 dark:text-gray-100">R2 WebDAV</h2>
        </div>

        <!-- Title -->
        <h1 class="text-2xl font-semibold text-gray-900 dark:text-gray-100 text-center mb-2">欢迎回来</h1>
        <p class="text-sm text-gray-500 dark:text-gray-400 text-center mb-10">登录以继续</p>

        <!-- Step 1: Username/Password -->
        <div id="step-password">
          <div class="floating-label-container mb-5">
            <input
              id="login-username"
              type="text"
              class="input-field"
              placeholder=" "
              autocomplete="username"
            />
            <label for="login-username" class="floating-label">用户名</label>
          </div>

          <div class="floating-label-container mb-8">
            <input
              id="login-password"
              type="password"
              class="input-field"
              placeholder=" "
              autocomplete="current-password"
            />
            <label for="login-password" class="floating-label">密码</label>
          </div>

          <button id="btn-login" class="btn-primary">
            登录
          </button>
        </div>

        <!-- Step 2: 2FA Verification -->
        <div id="step-2fa" class="hidden">
          <div class="mb-6 p-4 bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 border border-blue-200 dark:border-blue-700/50 rounded-xl shadow-sm">
            <div class="flex items-center space-x-2">
              <svg class="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
              </svg>
              <p class="text-sm font-medium text-gray-800 dark:text-gray-200">
                需要双因素认证，请输入验证码
              </p>
            </div>
          </div>

          <div class="mb-5">
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-3 text-center">
              请输入 6 位验证码
            </label>
            <div class="otp-container">
              <input id="otp-1" type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" autocomplete="off" />
              <input id="otp-2" type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" autocomplete="off" />
              <input id="otp-3" type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" autocomplete="off" />
              <span class="otp-separator">-</span>
              <input id="otp-4" type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" autocomplete="off" />
              <input id="otp-5" type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" autocomplete="off" />
              <input id="otp-6" type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" autocomplete="off" />
            </div>
            <input id="login-totp" type="hidden" autocomplete="one-time-code" />
          </div>

          <div id="recovery-section" class="hidden">
            <div class="floating-label-container mb-5">
              <input
                id="login-recovery"
                type="text"
                class="input-field"
                placeholder=" "
                autocomplete="off"
              />
              <label for="login-recovery" class="floating-label">恢复码</label>
            </div>
          </div>

          <div class="mb-5">
            <a id="link-lost-2fa" class="text-xs text-gray-500 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 cursor-pointer transition">
              丢失双因素认证？
            </a>
          </div>

          <button id="btn-2fa" class="btn-primary">
            验证
          </button>

          <button id="btn-back" class="btn-secondary mt-3">
            返回
          </button>
        </div>

        <!-- Divider -->
        <div class="relative my-8">
          <div class="absolute inset-0 flex items-center">
            <div class="w-full border-t border-gray-200 dark:border-gray-700"></div>
          </div>
          <div class="relative flex justify-center text-xs">
            <span class="px-3 bg-white dark:bg-gray-800 text-gray-500 dark:text-gray-400 font-medium">或</span>
          </div>
        </div>

        <!-- Passkey Login -->
        <button id="btn-passkey" class="btn-secondary flex items-center justify-center">
          <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path d="M15 7a2 2 0 1 1 2-2 2 2 0 0 1-2 2Zm0 0v9m0 0-3 3m3-3 3 3"/>
          </svg>
          使用通行密钥登录
        </button>

        <!-- Error Display -->
        <div id="login-error" class="hidden mt-5 text-sm font-medium text-red-700 dark:text-red-300 bg-gradient-to-r from-red-50 to-pink-50 dark:from-red-900/20 dark:to-pink-900/20 border border-red-300 dark:border-red-700/50 rounded-xl p-4 shadow-sm">
          <div class="flex items-center space-x-2">
            <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            <span id="login-error-text"></span>
          </div>
        </div>

      </div>
    </div>
  </div>
`;
}
