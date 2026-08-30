// ============================================================
// Qrypto — Real API Client
// Wraps fetch calls to the backend with JWT injection,
// error normalisation, type safety, network fault resilience,
// and safe URL formatting.
// Used when VITE_API_URL is configured.
// ============================================================

import type { Finding, MigrationTask, ServiceNode } from '../types';

// Strip trailing slashes to prevent double-slash URL bugs (e.g. http://localhost:3001//api/...)
const BASE_URL = (import.meta.env.VITE_API_URL || '').replace(/\/+$/, '');

// Token store — kept in memory (not localStorage) for security
let _token: string | null = null;

export function setToken(token: string | null) {
  _token = token;
}

export function getToken(): string | null {
  return _token;
}

export function isApiConfigured(): boolean {
  return !!import.meta.env.VITE_API_URL;
}

export class ApiError extends Error {
  public status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = 'ApiError';
  }
}

// Helper to construct normalized backend URLs
function buildUrl(path: string): string {
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  return `${BASE_URL}${cleanPath}`;
}

// Extract human-readable error messages from JSON error responses
async function parseErrorMessage(res: Response): Promise<string> {
  try {
    const body = await res.json();
    if (typeof body.error === 'string' && body.error.trim()) {
      return body.error;
    }
    if (body.error && typeof body.error.message === 'string' && body.error.message.trim()) {
      return body.error.message;
    }
    if (typeof body.message === 'string' && body.message.trim()) {
      return body.message;
    }
  } catch {
    // Ignore JSON parsing errors for 500 / non-JSON error pages
  }
  return res.statusText || `HTTP Error ${res.status}`;
}

// ── Generic fetch wrapper ─────────────────────────────────────

async function apiFetch<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  if (_token) {
    headers['Authorization'] = `Bearer ${_token}`;
  }

  const url = buildUrl(path);
  let res: Response;

  try {
    res = await fetch(url, {
      ...options,
      headers,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Network failure or CORS blocked request';
    throw new ApiError(0, `Network Connection Error: ${msg}`);
  }

  if (!res.ok) {
    const errorMsg = await parseErrorMessage(res);
    throw new ApiError(res.status, errorMsg);
  }

  // Handle 204 No Content or empty bodies gracefully
  if (res.status === 204 || res.headers.get('content-length') === '0') {
    return {} as T;
  }

  try {
    return (await res.json()) as T;
  } catch {
    throw new ApiError(res.status, 'Invalid JSON payload received from server');
  }
}

// ── Auth ──────────────────────────────────────────────────────

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: string;
}

export interface AuthResponse {
  token: string;
  user: AuthUser;
}

export const authApi = {
  login: (email: string, password: string) =>
    apiFetch<AuthResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),

  register: (email: string, password: string, name: string, role?: string) =>
    apiFetch<AuthResponse>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, name, role }),
    }),

  me: () => apiFetch<AuthUser>('/api/auth/me'),
};

// ── Scans ─────────────────────────────────────────────────────

export interface ScanListItem {
  id: string;
  projectName: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETE' | 'ERROR';
  progress: number;
  filesScanned: number;
  linesScanned: number;
  readinessScore: number | null;
  startedAt: string;
  completedAt: string | null;
  errorMessage: string | null;
  _count: { findings: number };
}

export interface ScanResult {
  id: string;
  projectName: string;
  status: string;
  progress: number;
  filesScanned: number;
  linesScanned: number;
  readinessScore: number | null;
  startedAt: string;
  completedAt: string | null;
  errorMessage: string | null;
  findings: Finding[];
  migrationTasks: MigrationTask[];
  services: ServiceNode[];
}

export const scansApi = {
  // Upload a zip file for scanning
  create: async (zipFile: File, projectName: string): Promise<{ scanId: string; status: string }> => {
    const formData = new FormData();
    formData.append('repository', zipFile);
    formData.append('projectName', projectName);

    const headers: Record<string, string> = {};
    if (_token) headers['Authorization'] = `Bearer ${_token}`;

    let res: Response;
    try {
      res = await fetch(buildUrl('/api/scans'), {
        method: 'POST',
        headers,
        body: formData,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Network failure or CORS blocked upload';
      throw new ApiError(0, `Upload Failed: ${msg}`);
    }

    if (!res.ok) {
      const errorMsg = await parseErrorMessage(res);
      throw new ApiError(res.status, errorMsg);
    }

    return res.json();
  },

  list: (page = 1, limit = 20) =>
    apiFetch<{ scans: ScanListItem[]; total: number; page: number; limit: number }>(
      `/api/scans?page=${page}&limit=${limit}`
    ),

  get: (scanId: string) => apiFetch<ScanResult>(`/api/scans/${encodeURIComponent(scanId)}`),

  // Poll scan progress until complete or errored with max retries and abort signal support
  pollUntilComplete: async (
    scanId: string,
    onProgress: (scan: ScanResult) => void,
    intervalMs = 1500,
    maxAttempts = 120, // 3 minutes timeout limit by default
    signal?: AbortSignal
  ): Promise<ScanResult> => {
    let attempts = 0;
    return new Promise((resolve, reject) => {
      let timerId: ReturnType<typeof setTimeout> | null = null;

      const cleanup = () => {
        if (timerId !== null) {
          clearTimeout(timerId);
          timerId = null;
        }
      };

      if (signal) {
        signal.addEventListener('abort', () => {
          cleanup();
          reject(new Error('Scan polling aborted by caller'));
        });
      }

      const poll = async () => {
        if (signal?.aborted) return;
        attempts++;

        if (attempts > maxAttempts) {
          cleanup();
          return reject(new Error('Scan polling timed out after maximum attempts'));
        }

        try {
          const scan = await scansApi.get(scanId);
          if (signal?.aborted) return;

          onProgress(scan);

          if (scan.status === 'COMPLETE') {
            cleanup();
            return resolve(scan);
          }
          if (scan.status === 'ERROR') {
            cleanup();
            return reject(new Error(scan.errorMessage || 'Scan processing failed on backend'));
          }

          timerId = setTimeout(poll, intervalMs);
        } catch (err) {
          cleanup();
          reject(err);
        }
      };

      poll();
    });
  },
};

// ── Findings ──────────────────────────────────────────────────

export const findingsApi = {
  list: (scanId: string, params: Record<string, string> = {}) => {
    const qs = new URLSearchParams(params).toString();
    const safeScanId = encodeURIComponent(scanId);
    return apiFetch<{ findings: Finding[]; total: number }>(`/api/findings/scan/${safeScanId}?${qs}`);
  },

  get: (findingId: string) => apiFetch<Finding>(`/api/findings/${encodeURIComponent(findingId)}`),

  updateStatus: (findingId: string, status: string, reason?: string) =>
    apiFetch<{ id: string; remediationStatus: string }>(
      `/api/findings/${encodeURIComponent(findingId)}/status`,
      {
        method: 'PATCH',
        body: JSON.stringify({ status, reason }),
      }
    ),
};

// ── Reports ───────────────────────────────────────────────────

export const reportsApi = {
  downloadJSON: (scanId: string) => buildUrl(`/api/reports/${encodeURIComponent(scanId)}/json`),
  downloadCSV: (scanId: string) => buildUrl(`/api/reports/${encodeURIComponent(scanId)}/csv`),
  downloadCBOM: (scanId: string) => buildUrl(`/api/reports/${encodeURIComponent(scanId)}/cbom`),
};

// ── Audit Log ─────────────────────────────────────────────────

export interface AuditLogEntry {
  id: string;
  action: string;
  targetId: string | null;
  metadata: Record<string, unknown> | null;
  timestamp: string;
}

export const auditApi = {
  list: (page = 1, limit = 50) =>
    apiFetch<{ entries: AuditLogEntry[]; total: number; page: number; limit: number }>(
      `/api/audit?page=${page}&limit=${limit}`
    ),
};
