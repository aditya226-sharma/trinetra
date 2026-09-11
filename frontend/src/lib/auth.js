// Dashboard session helpers: bearer token persistence (localStorage).
export const TOKEN_KEY = "trinetra_token";

export function getToken() {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable (private mode) — session simply won't persist */
  }
}

export function isAuthed() {
  return Boolean(getToken());
}