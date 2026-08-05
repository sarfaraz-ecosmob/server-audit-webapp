import axios from "axios";

export const api = axios.create({
  // Defaults to a relative same-origin path — nginx proxies "/api/*" to the
  // backend (see docker/nginx/nginx.conf), so this works unmodified whether
  // you access the app via localhost, a server IP, or a real domain, with
  // no CORS involved at all since same-origin requests never trigger it.
  // NEXT_PUBLIC_API_URL remains available as an override for anyone NOT
  // using the bundled proxy (e.g. calling the API cross-origin directly) —
  // but note it must be set at *build* time (docker build --build-arg), not
  // container start time, since Next.js inlines NEXT_PUBLIC_* at build time.
  baseURL: process.env.NEXT_PUBLIC_API_URL || "/api",
});

function readToken(): string | null {
  if (typeof window === "undefined") return null;
  // "Remember me" checked -> localStorage (survives browser close).
  // Unchecked -> sessionStorage only (cleared when the tab/browser closes).
  return localStorage.getItem("token") || sessionStorage.getItem("token");
}

api.interceptors.request.use((config) => {
  const token = readToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export function saveToken(token: string, remember: boolean = true) {
  if (remember) {
    localStorage.setItem("token", token);
    sessionStorage.removeItem("token");
  } else {
    sessionStorage.setItem("token", token);
    localStorage.removeItem("token");
  }
}

export function clearToken() {
  localStorage.removeItem("token");
  sessionStorage.removeItem("token");
}

export function isLoggedIn() {
  return !!readToken();
}
