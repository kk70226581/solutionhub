const STORAGE_KEY = 'solvenutIncomingCall';

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
      return;
    }
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(call));
  } catch {
    // ignore storage failures
  }
}

export function clearStoredIncomingCall() {
  setStoredIncomingCall(null);
}
