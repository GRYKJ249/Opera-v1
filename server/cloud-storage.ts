import { readFile } from 'node:fs/promises';

const base = (process.env.NEXTCLOUD_URL ?? 'http://127.0.0.1:8080').replace(/\/+$/, '');
const user = process.env.NEXTCLOUD_STORAGE_USER ?? 'opera_storage';
const passwordFile = process.env.NEXTCLOUD_STORAGE_PASSWORD_FILE ?? '/home/ubuntu/nextcloud-data/.opera_storage_password';
let passwordPromise: Promise<string> | null = null;

const getPassword = () => passwordPromise ??= readFile(passwordFile, 'utf8').then(v => v.trim());
const davBase = () => `${base}/remote.php/dav/files/${encodeURIComponent(user)}`;

function safeParts(input: string | null | undefined): string[] {
  const value = String(input ?? '').trim();
  if (value.length > 2048) throw new Error('path_too_long');
  const parts = value.split('/').filter(Boolean);
  if (parts.some(p => p === '.' || p === '..' || p.includes('\\') || /[\u0000-\u001f]/.test(p))) throw new Error('invalid_path');
  return parts;
}

function userPath(userId: number, input?: string | null): string {
  const parts = ['opera', String(userId), ...safeParts(input)];
  return parts.map(encodeURIComponent).join('/');
}

async function request(method: string, path: string, init: RequestInit = {}) {
  const password = await getPassword();
  const headers = new Headers(init.headers);
  headers.set('Authorization', `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`);
  headers.set('OCS-APIRequest', 'true');
  return fetch(`${davBase()}/${path}`, { ...init, method, headers, redirect: 'manual' });
}

async function ensureUserRoot(userId: number) {
  const root = userPath(userId);
  const parent = userPath(userId).split('/').slice(0, 1).join('/');
  const first = await request('MKCOL', parent);
  if (![201, 405, 301, 302].includes(first.status)) await first.arrayBuffer();
  const second = await request('MKCOL', root);
  if (![201, 405, 301, 302].includes(second.status)) throw new Error(`storage_root_${second.status}`);
}

export async function storageStatus() {
  const r = await request('PROPFIND', 'opera', { headers: { Depth: '0' } });
  return r.ok || r.status === 207;
}

export async function listFiles(userId: number, path?: string | null) {
  await ensureUserRoot(userId);
  const r = await request('PROPFIND', userPath(userId, path), { headers: { Depth: '1' } });
  if (r.status !== 207) throw new Error(`storage_list_${r.status}`);
  const xml = await r.text();
  const hrefs = [...xml.matchAll(/<(?:[\w-]+:)?href[^>]*>([\s\S]*?)<\/(?:[\w-]+:)?href>/gi)].map(m => decodeURIComponent(m[1].replace(/&amp;/g, '&')));
  const own = hrefs.filter(h => h !== hrefs[0]);
  return own.map(href => ({ name: decodeURIComponent(href.replace(/\/+$/, '').split('/').pop() ?? ''), href }));
}

export async function makeFolder(userId: number, path: string) {
  await ensureUserRoot(userId);
  const r = await request('MKCOL', userPath(userId, path));
  if (![201, 405].includes(r.status)) throw new Error(`storage_folder_${r.status}`);
}

export async function uploadFile(userId: number, path: string, body: Uint8Array, contentType = 'application/octet-stream') {
  await ensureUserRoot(userId);
  const r = await request('PUT', userPath(userId, path), { headers: { 'Content-Type': contentType }, body: body as BodyInit });
  if (!r.ok && r.status !== 201 && r.status !== 204) throw new Error(`storage_upload_${r.status}`);
}

export async function downloadFile(userId: number, path: string) {
  const r = await request('GET', userPath(userId, path));
  return r;
}

export async function deleteItem(userId: number, path: string) {
  const r = await request('DELETE', userPath(userId, path));
  if (!r.ok && r.status !== 404) throw new Error(`storage_delete_${r.status}`);
}

export { safeParts };
