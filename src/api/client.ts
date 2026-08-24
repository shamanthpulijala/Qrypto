// ============================================================
// Qrypto — Real API Client
// Wraps fetch calls to the backend with JWT injection,
// error normalisation, and type safety.
// Used when VITE_API_URL is configured.
// ============================================================

const BASE_URL = import.meta.env.VITE_API_URL || '';

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

  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new ApiError(res.status, body.error || res.statusText);
  }

  return res.json() as Promise<T>;
}

export class ApiError extends Error {
  public status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = 'ApiError';
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
  findings: any[];
  migrationTasks: any[];
  services: any[];
}

export const scansApi = {
  // Upload a zip file for scanning
  create: async (zipFile: File, projectName: string): Promise<{ scanId: string; status: string }> => {
    const formData = new FormData();
    formData.append('repository', zipFile);
    formData.append('projectName', projectName);

    const headers: Record<string, string> = {};
    if (_token) headers['Authorization'] = `Bearer ${_token}`;

    const res = await fetch(`${BASE_URL}/api/scans`, {
      method: 'POST',
      headers,
      body: formData,
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: res.statusText }));
      throw new ApiError(res.status, body.error || res.statusText);
    }

    return res.json();
  },

  list: (page = 1, limit = 20) =>
    apiFetch<{ scans: ScanListItem[]; total: number; page: number; limit: number }>(
      `/api/scans?page=${page}&limit=${limit}`
    ),

  get: (scanId: string) => apiFetch<ScanResult>(`/api/scans/${scanId}`),

  // Poll scan progress until complete or errored
  pollUntilComplete: async (
    scanId: string,
    onProgress: (scan: ScanResult) => void,
    intervalMs = 1500
  ): Promise<ScanResult> => {
    return new Promise((resolve, reject) => {
      const poll = async () => {
        try {
          const scan = await scansApi.get(scanId);
          onProgress(scan);

          if (scan.status === 'COMPLETE') return resolve(scan);
          if (scan.status === 'ERROR') return reject(new Error(scan.errorMessage || 'Scan failed'));

          setTimeout(poll, intervalMs);
        } catch (err) {
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
    return apiFetch<{ findings: any[]; total: number }>(`/api/findings/scan/${scanId}?${qs}`);
  },

  get: (findingId: string) => apiFetch<any>(`/api/findings/${findingId}`),

  updateStatus: (findingId: string, status: string, reason?: string) =>
    apiFetch<{ id: string; remediationStatus: string }>(`/api/findings/${findingId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, reason }),
    }),
};

// ── Reports ───────────────────────────────────────────────────

export const reportsApi = {
  downloadJSON: (scanId: string) => `${BASE_URL}/api/reports/${scanId}/json`,
  downloadCSV: (scanId: string) => `${BASE_URL}/api/reports/${scanId}/csv`,
  downloadCBOM: (scanId: string) => `${BASE_URL}/api/reports/${scanId}/cbom`,
};
