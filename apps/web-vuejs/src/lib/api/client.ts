const BASE_URL = '/api/spa'

let csrfInitialized = false

function getXsrfToken(): string | null {
  const match = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]*)/)
  return match?.[1] ? decodeURIComponent(match[1]) : null
}

export async function initCsrf(): Promise<void> {
  if (csrfInitialized) return
  await fetch('/sanctum/csrf-cookie', { credentials: 'include' })
  csrfInitialized = true
}

export interface ApiError {
  message: string
  errors?: Record<string, string[]>
  status: number
}

export async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {},
): Promise<T> {
  const url = `${BASE_URL}${endpoint}`

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  }

  const xsrfToken = getXsrfToken()
  if (xsrfToken) {
    headers['X-XSRF-TOKEN'] = xsrfToken
  }

  const response = await fetch(url, {
    ...options,
    headers,
    credentials: 'include',
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Request failed' }))
    const apiError: ApiError = {
      message: error.message || `HTTP error ${response.status}`,
      errors: error.errors,
      status: response.status,
    }
    throw apiError
  }

  return response.json()
}
