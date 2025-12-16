/**
 * Generate authentication JavaScript for login page
 * @param sessionKey - Session storage key
 * @returns JavaScript code as string
 */
export function generateLoginScript(sessionKey: string): string {
	return `
    const SESSION_KEY = '${sessionKey}';

    // Floating Label Logic
    const initFloatingLabels = () => {
      const inputs = document.querySelectorAll('.floating-label-container input');
      inputs.forEach(input => {
        const updateLabel = () => {
          if (input.value) {
            input.classList.add('has-value');
          } else {
            input.classList.remove('has-value');
          }
        };

        // Initial check
        updateLabel();

        // Listen for changes
        input.addEventListener('input', updateLabel);
        input.addEventListener('change', updateLabel);

        // Handle autofill
        setTimeout(updateLabel, 100);
      });
    };

    // Initialize on load
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initFloatingLabels);
    } else {
      initFloatingLabels();
    }

    // Session Management
    const saveSession = (session) => {
      try {
        localStorage.setItem(SESSION_KEY, JSON.stringify(session || {}));
      } catch (e) {
        console.error('Failed to save session:', e);
      }
    };

    // Error Handling
    let errorAutoHideTimeout = null;
    let errorHideAnimationTimeout = null;

    const showError = (message) => {
      const errorBox = document.getElementById('login-error');
      const errorText = document.getElementById('login-error-text');
      if (errorBox && errorText) {
        // Clear any existing timeouts
        if (errorAutoHideTimeout) {
          clearTimeout(errorAutoHideTimeout);
        }
        if (errorHideAnimationTimeout) {
          clearTimeout(errorHideAnimationTimeout);
        }

        errorText.textContent = message;
        errorBox.classList.remove('hidden', 'hide');
        errorBox.classList.add('show');

        // Remove animation class after animation completes
        setTimeout(() => {
          errorBox.classList.remove('show');
        }, 600);

        // Auto-hide after 5 seconds
        errorAutoHideTimeout = setTimeout(() => {
          hideError();
        }, 5000);
      }
    };

    const hideError = () => {
      const errorBox = document.getElementById('login-error');
      if (errorBox) {
        // Clear auto-hide timeout if hiding manually
        if (errorAutoHideTimeout) {
          clearTimeout(errorAutoHideTimeout);
          errorAutoHideTimeout = null;
        }

        errorBox.classList.remove('show');
        errorBox.classList.add('hide');

        // Hide element after animation completes
        errorHideAnimationTimeout = setTimeout(() => {
          errorBox.classList.add('hidden');
          errorBox.classList.remove('hide');
        }, 300);
      }
    };

    // State Management
    let partialToken = '';
    let currentUsername = '';
    document.getElementById('btn-login')?.addEventListener('click', async () => {
      hideError();

      const username = document.getElementById('login-username')?.value.trim();
      const password = document.getElementById('login-password')?.value.trim();

      if (!username || !password) {
        showError('请输入用户名和密码。');
        return;
      }

      try {
        const response = await fetch('/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password }),
        });

        const data = await response.json();

        if (!response.ok) {
          showError(data.error || '登录失败，请检查您的凭据。');
          return;
        }

        // Check if 2FA is required
        if (data.requires2FA) {
          partialToken = data.partialToken;
          currentUsername = username;

          // Switch to 2FA step
          document.getElementById('step-password')?.classList.add('hidden');
          document.getElementById('step-2fa')?.classList.remove('hidden');
          document.getElementById('login-totp')?.focus();
          return;
        }

        // No 2FA required - save tokens and redirect
        saveSession({
          url: window.location.origin,
          accessToken: data.accessToken,
          refreshToken: data.refreshToken,
          expiresAt: Date.now() + (data.expiresIn || 900) * 1000,
          user: data.user || { username },
        });

        window.location.href = '/';
      } catch (error) {
        console.error('Login error:', error);
        showError('无法连接到服务器，请重试。');
      }
    });

    // Handle Enter key for password input
    document.getElementById('login-password')?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        document.getElementById('btn-login')?.click();
      }
    });

    // Step 2: 2FA Verification
    document.getElementById('btn-2fa')?.addEventListener('click', async () => {
      hideError();

      const totpCode = document.getElementById('login-totp')?.value.trim();
      const recoveryCode = document.getElementById('login-recovery')?.value.trim();

      if (!partialToken) {
        showError('会话已过期，请重新登录。');
        return;
      }

      if (!totpCode && !recoveryCode) {
        showError('请输入 TOTP 验证码或恢复代码。');
        return;
      }

      try {
        const response = await fetch('/auth/2fa/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            partialToken,
            code: totpCode,
            recoveryCode: recoveryCode || undefined,
          }),
        });

        const data = await response.json();

        if (!response.ok) {
          showError(data.error || '双因素验证失败，请重试。');
          return;
        }

        // Save tokens and redirect
        saveSession({
          url: window.location.origin,
          accessToken: data.accessToken,
          refreshToken: data.refreshToken,
          expiresAt: Date.now() + (data.expiresIn || 900) * 1000,
          user: data.user || { username: currentUsername },
        });

        window.location.href = '/';
      } catch (error) {
        console.error('2FA verification error:', error);
        showError('无法验证双因素认证，请重试。');
      }
    });

    // Handle Enter key for TOTP input
    document.getElementById('login-totp')?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        document.getElementById('btn-2fa')?.click();
      }
    });

    // Back to login button
    document.getElementById('btn-back')?.addEventListener('click', () => {
      partialToken = '';
      currentUsername = '';
      document.getElementById('step-2fa')?.classList.add('hidden');
      document.getElementById('step-password')?.classList.remove('hidden');
      document.getElementById('login-totp').value = '';
      document.getElementById('login-recovery').value = '';
      hideError();
    });

    // Step 3: WebAuthn Passkey Login
    document.getElementById('btn-passkey')?.addEventListener('click', async () => {
      hideError();

      try {
        // Start passkey authentication
        const startResponse = await fetch('/auth/passkey/authenticate/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: '' }),
        });

        const startData = await startResponse.json();

        if (!startResponse.ok) {
          showError(startData.error || '无法初始化 Passkey 认证。');
          return;
        }

        // Prepare credential request options
        const options = startData.options;

        // Decode challenge from base64url
        const challengeB64 = options.challenge.replace(/-/g, '+').replace(/_/g, '/');
        const paddedChallenge = challengeB64 + '='.repeat((4 - challengeB64.length % 4) % 4);
        options.challenge = Uint8Array.from(atob(paddedChallenge), c => c.charCodeAt(0));

        // Decode credential IDs if present
        if (options.allowCredentials) {
          options.allowCredentials = options.allowCredentials.map(cred => {
            const credIdB64 = cred.id.replace(/-/g, '+').replace(/_/g, '/');
            const paddedCredId = credIdB64 + '='.repeat((4 - credIdB64.length % 4) % 4);
            return {
              ...cred,
              id: Uint8Array.from(atob(paddedCredId), c => c.charCodeAt(0)),
            };
          });
        }

        // Request credential from browser
        const credential = await navigator.credentials.get({ publicKey: options });

        if (!credential) {
          showError('Passkey 认证已取消。');
          return;
        }

        // Encode credential response using base64url
        const arrayBufferToBase64url = (buffer) => {
          const bytes = new Uint8Array(buffer);
          let binary = '';
          for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
          }
          return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
        };

        const credentialData = {
          id: credential.id,
          rawId: arrayBufferToBase64url(credential.rawId),
          type: credential.type,
          response: {
            authenticatorData: arrayBufferToBase64url(credential.response.authenticatorData),
            clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
            signature: arrayBufferToBase64url(credential.response.signature),
            userHandle: credential.response.userHandle
              ? arrayBufferToBase64url(credential.response.userHandle)
              : null,
          },
          clientExtensionResults: credential.getClientExtensionResults(),
        };

        // Finish passkey authentication
        const finishResponse = await fetch('/auth/passkey/authenticate/finish', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            credential: credentialData,
            challengeId: startData.challengeId,
          }),
        });

        const finishData = await finishResponse.json();

        if (!finishResponse.ok) {
          showError(finishData.error || 'Passkey 认证失败。');
          return;
        }

        // Save tokens and redirect
        saveSession({
          url: window.location.origin,
          accessToken: finishData.accessToken,
          refreshToken: finishData.refreshToken,
          expiresAt: Date.now() + (finishData.expiresIn || 900) * 1000,
          user: finishData.user || { username },
        });

        window.location.href = '/';
      } catch (error) {
        console.error('Passkey error:', error);

        if (error.name === 'NotAllowedError') {
          showError('Passkey 认证已取消或不被允许。');
        } else if (error.name === 'NotSupportedError') {
          showError('您的浏览器不支持 Passkey 认证。');
        } else {
          showError('Passkey 认证失败，请尝试其他方法。');
        }
      }
    });

    // Focus username field on load
  `;
}
