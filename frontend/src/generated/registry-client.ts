export type RegistryRecord = {
  id: string;
  status?: string;
  state?: string;
  created_at?: string;
  updated_at?: string;
} & Record<string, unknown>;

export type CursorPage<TItem extends RegistryRecord = RegistryRecord> = {
  items: TItem[];
  next_cursor: string | null;
  has_more: boolean;
};

export type RegistryQuery = {
  cursor?: string | null;
  limit?: number;
  search?: string;
  status?: string;
  state?: string;
  room_id?: string;
  agent_id?: string;
  resource_id?: string;
} & Record<string, string | number | null | undefined>;

async function request<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' }
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json() as Promise<T>;
}

function queryString(params: RegistryQuery) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      query.set(key, String(value));
    }
  });
  return query.toString() ? `?${query.toString()}` : '';
}

export const registryApi = {
  list: <TItem extends RegistryRecord = RegistryRecord>(path: string, params: RegistryQuery = {}) =>
    request<CursorPage<TItem>>(`/api/registry/${path}${queryString(params)}`)
};
