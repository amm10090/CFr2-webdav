/**
 * Custom CSS styles for login page
 */
export const LOGIN_STYLES = `
    * { box-sizing: border-box; }
    .animate-fade-in { animation: fade 0.4s ease-out; }
    @keyframes fade { from {opacity: 0; transform: translateY(-8px);} to {opacity: 1; transform: translateY(0);} }
    .btn-primary {
      width: 100%;
      padding: 0.75rem;
      background-color: var(--color-gray-900);
      color: var(--color-white);
      border-radius: 14px;
      font-weight: var(--font-weight-medium);
      box-shadow: 0 1px 3px 0 rgba(0,0,0,0.1), 0 1px 2px -1px rgba(0,0,0,0.1);
      transition: all 0.3s cubic-bezier(0.4,0,0.2,1);
    }
    .btn-primary:hover {
      background-color: var(--color-gray-800);
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -2px rgba(0,0,0,0.1);
    }
    @media (prefers-color-scheme: dark) {
      .btn-primary {
        background-color: var(--color-white);
        color: var(--color-gray-900);
      }
      .btn-primary:hover {
        background-color: var(--color-gray-100);
      }
    }
    .btn-secondary {
      width: 100%;
      padding: 0.75rem;
      border: 1px solid var(--color-gray-300);
      border-radius: 14px;
      color: var(--color-gray-700);
      font-weight: var(--font-weight-medium);
      box-shadow: 0 1px 3px 0 rgba(0,0,0,0.1), 0 1px 2px -1px rgba(0,0,0,0.1);
      transition: all 0.3s cubic-bezier(0.4,0,0.2,1);
    }
    .btn-secondary:hover {
      background-color: var(--color-gray-50);
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -2px rgba(0,0,0,0.1);
    }
    @media (prefers-color-scheme: dark) {
      .btn-secondary {
        border-color: var(--color-gray-700);
        color: var(--color-gray-300);
      }
      .btn-secondary:hover {
        background-color: var(--color-gray-800);
      }
    }
    /* Floating label container */
    .floating-label-container {
      position: relative;
    }

    .input-field {
      width: 100%;
      padding: 1.25rem 1rem 0.5rem 1rem;
      border-radius: 12px;
      border: 2px solid var(--color-gray-300);
      background-color: var(--color-white);
      color: var(--color-gray-900);
      box-shadow: inset 0 2px 4px rgba(0,0,0,0.06);
      transition: all 0.3s cubic-bezier(0.4,0,0.2,1);
    }

    .floating-label {
      position: absolute;
      left: 1rem;
      top: 50%;
      transform: translateY(-50%);
      color: var(--color-gray-500);
      font-size: 0.875rem;
      pointer-events: none;
      transition: all 0.3s cubic-bezier(0.4,0,0.2,1);
      background-color: transparent;
    }

    .input-field:focus ~ .floating-label,
    .input-field:not(:placeholder-shown) ~ .floating-label,
    .input-field.has-value ~ .floating-label {
      top: 0.5rem;
      transform: translateY(0);
      font-size: 0.75rem;
      color: var(--color-blue-500);
    }
    .input-field:focus {
      outline: none;
      border-color: var(--color-blue-500);
      box-shadow: 0 0 0 3px rgba(48,128,255,0.15);
      transform: translateY(-1px);
    }
    @media (prefers-color-scheme: dark) {
      .input-field {
        border-color: var(--color-gray-600);
        background-color: var(--color-gray-800);
        color: var(--color-gray-100);
        box-shadow: inset 0 2px 4px rgba(0,0,0,0.2);
      }
      .input-field:focus {
        border-color: var(--color-blue-400);
        box-shadow: 0 0 0 3px rgba(48,128,255,0.12);
        transform: translateY(-1px);
      }
      .floating-label {
        color: var(--color-gray-400);
      }
      .input-field:focus ~ .floating-label,
      .input-field:not(:placeholder-shown) ~ .floating-label,
      .input-field.has-value ~ .floating-label {
        color: var(--color-blue-400);
      }
    }

    /* OTP Input Container */
    .otp-container {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
    }

    .otp-input {
      width: 48px;
      height: 48px;
      text-align: center;
      font-size: 1.25rem;
      font-weight: 600;
      border-radius: 12px;
      border: 2px solid var(--color-gray-300);
      background-color: var(--color-white);
      color: var(--color-gray-900);
      box-shadow: inset 0 2px 4px rgba(0,0,0,0.06);
      transition: all 0.2s cubic-bezier(0.4,0,0.2,1);
      caret-color: var(--color-blue-500);
    }

    .otp-input:focus {
      outline: none;
      border-color: var(--color-blue-500);
      box-shadow: 0 0 0 3px rgba(48,128,255,0.15);
      transform: scale(1.05);
    }

    .otp-input.filled {
      border-color: var(--color-blue-500);
      background-color: var(--color-blue-50);
    }

    .otp-separator {
      color: var(--color-gray-400);
      font-size: 1.5rem;
      font-weight: 600;
      user-select: none;
      margin: 0 0.25rem;
    }

    @media (prefers-color-scheme: dark) {
      .otp-input {
        border-color: var(--color-gray-600);
        background-color: var(--color-gray-800);
        color: var(--color-gray-100);
        box-shadow: inset 0 2px 4px rgba(0,0,0,0.2);
        caret-color: var(--color-blue-400);
      }
      .otp-input:focus {
        border-color: var(--color-blue-400);
        box-shadow: 0 0 0 3px rgba(48,128,255,0.12);
      }
      .otp-input.filled {
        border-color: var(--color-blue-400);
        background-color: var(--color-blue-900);
      }
      .otp-separator {
        color: var(--color-gray-500);
      }
    }

    @media (max-width: 640px) {
      .otp-input {
        width: 42px;
        height: 42px;
        font-size: 1.125rem;
      }
      .otp-container {
        gap: 0.375rem;
      }
    }

    /* Organic blob container */
    .blob-container {
      position: absolute;
      inset: 0;
      pointer-events: none;
      z-index: 0;
      overflow: hidden;
    }

    /* Organic blob base styles */
    .organic-blob {
      position: absolute;
      filter: blur(40px);
      opacity: 0.4;
      will-change: border-radius;
      transform: translateZ(0);
      animation: morph 9s ease-in-out infinite;
    }

    /* Morph animation for organic shapes */
    @keyframes morph {
      0%, 100% { border-radius: 63% 37% 54% 46% / 55% 48% 52% 45%; }
      25% { border-radius: 48% 52% 68% 32% / 42% 61% 39% 58%; }
      50% { border-radius: 40% 60% 42% 58% / 65% 38% 62% 35%; }
      75% { border-radius: 58% 42% 51% 49% / 48% 65% 35% 52%; }
    }

    /* Blob 1 - Top left */
    .blob-1 {
      width: 400px;
      height: 400px;
      top: -10%;
      left: -5%;
      background: radial-gradient(ellipse at 30% 40%,
        var(--color-blue-400) 0%,
        var(--color-gray-300) 70%,
        transparent 100%);
      animation-duration: 10s;
      animation-delay: 0s;
    }

    /* Blob 2 - Bottom right */
    .blob-2 {
      width: 350px;
      height: 350px;
      bottom: -15%;
      right: -10%;
      background: radial-gradient(ellipse at 70% 60%,
        var(--color-gray-400) 0%,
        var(--color-blue-300) 70%,
        transparent 100%);
      animation-duration: 9s;
      animation-delay: -3s;
    }

    /* Blob 3 - Middle right */
    .blob-3 {
      width: 300px;
      height: 300px;
      top: 50%;
      right: -5%;
      background: radial-gradient(ellipse at 50% 50%,
        var(--color-gray-300) 0%,
        var(--color-blue-200) 70%,
        transparent 100%);
      animation-duration: 8s;
      animation-delay: -6s;
    }

    /* Dark mode blob adjustments */
    @media (prefers-color-scheme: dark) {
      .organic-blob {
        opacity: 0.25;
        filter: blur(50px);
      }

      .blob-1 {
        background: radial-gradient(ellipse at 30% 40%,
          var(--color-blue-800) 0%,
          var(--color-gray-700) 70%,
          transparent 100%);
      }

      .blob-2 {
        background: radial-gradient(ellipse at 70% 60%,
          var(--color-gray-800) 0%,
          var(--color-blue-900) 70%,
          transparent 100%);
      }

      .blob-3 {
        background: radial-gradient(ellipse at 50% 50%,
          var(--color-gray-700) 0%,
          var(--color-blue-800) 70%,
          transparent 100%);
      }
    }

    /* Login card hover effect */
    .login-card {
      border-radius: 32px !important;
      transition: transform 0.4s cubic-bezier(0.4, 0, 0.2, 1),
                  box-shadow 0.4s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .login-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 12px 24px -4px rgba(0,0,0,0.12),
                  0 4px 8px -2px rgba(0,0,0,0.08);
    }

    /* Enhanced button transitions */
    .btn-primary, .btn-secondary {
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .btn-primary:hover {
      transform: translateY(-1px) scale(1.01);
    }

    .btn-secondary:hover {
      transform: translateY(-1px);
    }

    /* Error message animations */
    @keyframes slideInShake {
      0% {
        opacity: 0;
        transform: translateY(-10px);
      }
      50% {
        opacity: 1;
        transform: translateY(0);
      }
      60% {
        transform: translateX(-4px);
      }
      70% {
        transform: translateX(4px);
      }
      80% {
        transform: translateX(-2px);
      }
      90% {
        transform: translateX(2px);
      }
      100% {
        transform: translateX(0);
      }
    }

    @keyframes fadeOut {
      from {
        opacity: 1;
        transform: translateY(0);
      }
      to {
        opacity: 0;
        transform: translateY(-8px);
      }
    }

    #login-error {
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    #login-error.show {
      animation: slideInShake 0.6s cubic-bezier(0.4, 0, 0.2, 1);
    }

    #login-error.hide {
      animation: fadeOut 0.3s cubic-bezier(0.4, 0, 0.2, 1) forwards;
    }

    /* Reduced motion support */
    @media (prefers-reduced-motion: reduce) {
      .organic-blob {
        animation: none;
      }
      .login-card:hover, .input-field:focus, .btn-primary:hover, .btn-secondary:hover {
        transform: none;
      }
      #login-error.show {
        animation: none;
      }
      #login-error.hide {
        animation: none;
      }
    }
`;
