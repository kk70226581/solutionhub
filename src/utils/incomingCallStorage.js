const STORAGE_KEY = 'solvenutIncomingCall';
const CHANGE_EVENT = 'solvenut-incoming-call-changed';

export function getStoredIncomingCall() {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function setStoredIncomingCall(call) {
  try {
    if (!call) {
      sessionStorage.removeItem(STORAGE_KEY);
    } else {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(call));
    }
  } catch {
    // ignore storage failures
  }

  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(CHANGE_EVENT, { detail: call || null }));
  }
}

export function clearStoredIncomingCall() {
  setStoredIncomingCall(null);
}

export function subscribeToIncomingCallChanges(listener) {
  if (typeof window === 'undefined') return () => {};
  const handleChange = (event) => listener(event.detail || null);
  window.addEventListener(CHANGE_EVENT, handleChange);
  return () => window.removeEventListener(CHANGE_EVENT, handleChange);
}
