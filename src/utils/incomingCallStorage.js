const STORAGE_KEY = 'solvenutIncomingCall';
const CHANGE_EVENT = 'solvenut-incoming-call-changed';
const MAX_CALL_AGE_MS = 60_000;

export function getStoredIncomingCall() {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const call = JSON.parse(raw);
    const receivedAt = Number(call?.at || 0);
    if (!call?.room || !call?.offer || !receivedAt || Date.now() - receivedAt > MAX_CALL_AGE_MS) {
      sessionStorage.removeItem(STORAGE_KEY);
      return null;
    }
    return call;
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
