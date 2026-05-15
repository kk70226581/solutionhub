const GOOGLE_SCRIPT_SRC = 'https://accounts.google.com/gsi/client';

let googleScriptPromise = null;
let googleConfigPromise = null;

export const loadGoogleIdentityScript = () => {
  if (typeof window === 'undefined') {
    return Promise.reject(new Error('Google sign-in is available in the browser only.'));
  }

  if (window.google?.accounts?.id) {
    return Promise.resolve(window.google);
  }

  if (!googleScriptPromise) {
    googleScriptPromise = new Promise((resolve, reject) => {
      const existing = document.querySelector(`script[src="${GOOGLE_SCRIPT_SRC}"]`);
      if (existing) {
        existing.addEventListener('load', () => resolve(window.google), { once: true });
        existing.addEventListener('error', () => reject(new Error('Could not load Google sign-in.')), {
          once: true,
        });
        return;
      }

      const script = document.createElement('script');
      script.src = GOOGLE_SCRIPT_SRC;
      script.async = true;
      script.defer = true;
      script.onload = () => resolve(window.google);
      script.onerror = () => reject(new Error('Could not load Google sign-in.'));
      document.head.appendChild(script);
    });
  }

  return googleScriptPromise;
};

export const getGoogleClientId = async (apiBase) => {
  if (!googleConfigPromise) {
    googleConfigPromise = fetch(`${apiBase}/api/google-auth-config`)
      .then((res) => res.json())
      .then((data) => {
        if (!data.googleClientId) {
          throw new Error('Google login is not configured yet.');
        }
        return data.googleClientId;
      });
  }

  return googleConfigPromise;
};

export const saveAuthSession = (data) => {
  localStorage.setItem('token', data.token);
  localStorage.setItem('username', data.name || '');
  localStorage.setItem('name', data.name || '');
  localStorage.setItem('email', data.email || '');
  localStorage.setItem('role', String(data.role || 'client').toLowerCase());
};
