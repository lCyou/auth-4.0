// API通信用のユーティリティ

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

export interface ApiResponse<T> {
  data?: T;
  error?: string;
  message?: string;
}

export interface Client {
  id: string;
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  scope: string;
  client_name: string;
  created_at: string;
  updated_at: string;
}

export interface User {
  id: string;
  email: string;
  name: string;
  picture?: string;
  provider: string;
  provider_user_id: string;
  created_at: string;
  updated_at: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  session_token: string;
  expires_at: string;
  admin: {
    id: string;
    username: string;
    email: string;
  };
}

// 認証トークンを取得
export function getAuthToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('admin_token');
}

// 認証トークンを保存
export function setAuthToken(token: string): void {
  if (typeof window === 'undefined') return;
  localStorage.setItem('admin_token', token);
}

// 認証トークンを削除
export function removeAuthToken(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem('admin_token');
}

// APIリクエストのヘルパー関数
async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<ApiResponse<T>> {
  const token = getAuthToken();
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  if (token) {
    headers['X-Session-Token'] = token;
  }

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      return {
        error: errorData.error || errorData.message || `HTTP error ${response.status}`,
      };
    }

    const data = await response.json();
    return { data };
  } catch (error) {
    return {
      error: error instanceof Error ? error.message : 'Network error',
    };
  }
}

// 管理者ログイン
export async function adminLogin(
  credentials: LoginRequest
): Promise<ApiResponse<LoginResponse>> {
  return apiRequest<LoginResponse>('/api/admin/login', {
    method: 'POST',
    body: JSON.stringify(credentials),
  });
}

// 管理者ログアウト
export async function adminLogout(): Promise<ApiResponse<{ message: string }>> {
  const result = await apiRequest<{ message: string }>('/api/admin/logout', {
    method: 'POST',
  });
  removeAuthToken();
  return result;
}

// クライアント一覧取得
export async function listClients(): Promise<ApiResponse<Client[]>> {
  return apiRequest<Client[]>('/api/admin/clients');
}

// クライアント作成
export async function createClient(
  client: Omit<Client, 'id' | 'created_at' | 'updated_at'>
): Promise<ApiResponse<Client>> {
  return apiRequest<Client>('/api/admin/clients', {
    method: 'POST',
    body: JSON.stringify(client),
  });
}

// クライアント取得
export async function getClient(id: string): Promise<ApiResponse<Client>> {
  return apiRequest<Client>(`/api/admin/clients/${id}`);
}

// クライアント削除
export async function deleteClient(id: string): Promise<ApiResponse<{ message: string }>> {
  return apiRequest<{ message: string }>(`/api/admin/clients/${id}`, {
    method: 'DELETE',
  });
}

// ユーザー一覧取得
export async function listUsers(): Promise<ApiResponse<User[]>> {
  return apiRequest<User[]>('/api/admin/users');
}

// ユーザー取得
export async function getUser(id: string): Promise<ApiResponse<User>> {
  return apiRequest<User>(`/api/admin/users/${id}`);
}

// ユーザー削除
export async function deleteUser(id: string): Promise<ApiResponse<{ message: string }>> {
  return apiRequest<{ message: string }>(`/api/admin/users/${id}`, {
    method: 'DELETE',
  });
}
