const GOOGLE_SCRIPT_SRC = 'https://accounts.google.com/gsi/client';

let googleScriptPromise = null;
let googleConfigPromise = null;

export const loadGoogleIdentityScript = (timeout = 5000) => {
  if (typeof window === 'undefined') {
    return Promise.reject(new Error('Google sign-in is available in the browser only.'));
  }

  if (window.google?.accounts?.id) {
    return Promise.resolve(window.google);
  }

  if (!googleScriptPromise) {
    googleScriptPromise = new Promise((resolve, reject) => {
      const existing = document.querySelector(`script[src="${GOOGLE_SCRIPT_SRC}"]`);
      
      // Setup timeout
      const timeoutId = setTimeout(() => {
        reject(new Error('Google sign-in took too long to load. Please check your internet connection.'));
      }, timeout);

      const cleanup = () => clearTimeout(timeoutId);

      if (existing) {
        existing.addEventListener('load', () => {
          cleanup();
          resolve(window.google);
        }, { once: true });
        existing.addEventListener('error', () => {
          cleanup();
          reject(new Error('Failed to load Google sign-in. Please refresh and try again.'));
        }, { once: true });
        return;
      }

      const script = document.createElement('script');
      script.src = GOOGLE_SCRIPT_SRC;
      script.async = true;
      script.defer = true;
      script.onload = () => {
        cleanup();
        resolve(window.google);
      };
      script.onerror = () => {
        cleanup();
        googleScriptPromise = null; // Reset for retry
        reject(new Error('Failed to load Google sign-in. Please refresh and try again.'));
      };
      document.head.appendChild(script);
    });
  }

  return googleScriptPromise;
};

export const getGoogleClientId = async (apiBase) => {
  if (!googleConfigPromise) {
    googleConfigPromise = (async () => {
      try {
        const res = await fetch(`${apiBase}/api/google-auth-config`, {
          signal: AbortSignal.timeout(8000)
        });
        
        if (!res.ok) {
          throw new Error(`Configuration failed with status ${res.status}`);
        }
        
        const data = await res.json();
        
        if (!data.googleClientId) {
          throw new Error('Google login is not configured on the server.');
        }
        
        return data.googleClientId;
      } catch (err) {
        googleConfigPromise = null; // Reset for retry
        throw err;
      }
    })();
  }

  return googleConfigPromise;
};

export const saveAuthSession = (data) => {
  if (typeof window === 'undefined') return;
  
  try {
    localStorage.setItem('token', data.token || '');
    localStorage.setItem('username', data.name || '');
    localStorage.setItem('name', data.name || '');
    localStorage.setItem('email', data.email || '');
    localStorage.setItem('role', String(data.role || 'client').toLowerCase());
  } catch (err) {
    console.error('Failed to save auth session:', err);
  }
};

export const clearAuthSession = () => {
  if (typeof window === 'undefined') return;
  
  try {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    localStorage.removeItem('name');
    localStorage.removeItem('email');
    localStorage.removeItem('role');
  } catch (err) {
    console.error('Failed to clear auth session:', err);
  }
};
