const API_BASE = "/api/spa";

export interface ApiError {
  message: string;
  errors?: Record<string, string[]>;
  status: number;
}

// =========================================================================
// Token refresh queue (prevents concurrent refresh calls)
// =========================================================================

let isRefreshing = false;
let refreshSubscribers: ((success: boolean) => void)[] = [];

function subscribeTokenRefresh(callback: (success: boolean) => void): void {
  refreshSubscribers.push(callback);
}

function onTokenRefreshed(success: boolean): void {
  refreshSubscribers.forEach((callback) => callback(success));
  refreshSubscribers = [];
}

async function refreshAccessToken(): Promise<boolean> {
  if (isRefreshing) {
    return new Promise((resolve) => subscribeTokenRefresh(resolve));
  }

  isRefreshing = true;

  try {
    const response = await fetch(`${API_BASE}/auth/token/refresh`, {
      method: "POST",
      headers: {
        Accept: "application/json",
      },
      credentials: "include",
    });

    const success = response.ok;
    onTokenRefreshed(success);
    return success;
  } catch {
    onTokenRefreshed(false);
    return false;
  } finally {
    isRefreshing = false;
  }
}

// =========================================================================
// Authenticated API requests (Passport token via HttpOnly cookies)
// =========================================================================

export async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {},
  retry = true,
): Promise<T> {
  const url = `${API_BASE}${endpoint}`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
    ...((options.headers as Record<string, string>) || {}),
  };

  const response = await fetch(url, {
    ...options,
    headers,
    credentials: "include",
  });

  // Auto-refresh on 401
  if (response.status === 401 && retry) {
    const refreshed = await refreshAccessToken();
    if (refreshed) {
      return apiRequest<T>(endpoint, options, false);
    }
  }

  if (!response.ok) {
    const error = await response
      .json()
      .catch(() => ({ message: "Request failed" }));
    const apiError: ApiError = {
      message: error.message || `HTTP error ${response.status}`,
      errors: error.errors,
      status: response.status,
    };
    throw apiError;
  }

  return response.json();
}

// =========================================================================
// Auth functions (Passport token with HttpOnly cookies)
// =========================================================================

export async function login(credentials: {
  email: string;
  password: string;
}): Promise<{ user: unknown }> {
  const response = await fetch(`${API_BASE}/auth/token/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(credentials),
    credentials: "include",
  });

  if (!response.ok) {
    const error = await response
      .json()
      .catch(() => ({ message: "Login failed" }));
    throw {
      message: error.message || "Login failed",
      errors: error.errors,
      status: response.status,
    } as ApiError;
  }

  const data = await response.json();
  return { user: data.data.user };
}

export async function register(data: {
  name: string;
  email: string;
  password: string;
  password_confirmation: string;
}): Promise<{ user: unknown }> {
  const response = await fetch(`${API_BASE}/auth/token/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(data),
    credentials: "include",
  });

  if (!response.ok) {
    const error = await response
      .json()
      .catch(() => ({ message: "Registration failed" }));
    throw {
      message: error.message || "Registration failed",
      errors: error.errors,
      status: response.status,
    } as ApiError;
  }

  const responseData = await response.json();
  return { user: responseData.data.user };
}

export async function logout(): Promise<void> {
  await apiRequest("/auth/token/logout", { method: "POST" });
}

export async function getCurrentUser(): Promise<unknown | null> {
  try {
    const response = await apiRequest<{ data: unknown }>("/me");
    return response.data;
  } catch (error) {
    const err = error as ApiError;
    if (err.status === 401 || err.status === 403) {
      return null;
    }
    throw error;
  }
}
