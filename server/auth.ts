import { createHash, randomBytes } from 'node:crypto';
import type { Database, DatabaseTransaction } from './db.ts';
import { verifyPassword } from './password.ts';
import { recoverOwner } from './dev.ts';

const DEV_MODE = process.env.OPERA_DEV_MODE === '1';
const DUMMY_HASH = 'scrypt$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA==$' + Buffer.alloc(64).toString('base64');
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

export interface SessionUser { id: number; email: string; displayName: string | null; roles: string[]; mustChangePassword: boolean }
export type LoginResult =
  | { ok: true; token: string; maxAgeSec: number; user: SessionUser; restored?: 'reactivated' | 'recreated' }
  | { ok: false; code: 'invalid' | 'locked' | 'blocked' | 'pending' };

async function userById(db: Database | DatabaseTransaction, id: number): Promise<SessionUser | null> {
  const user = await db.prepare("SELECT id, email, display_name, must_change_password m FROM users WHERE id = ? AND status = 'active'").get(id);
  if (!user) return null;
  const roleRow = await db.prepare('SELECT roles FROM v_user_access WHERE user_id = ?').get(id);
  return {
    id: Number(user.id),
    email: user.email,
    displayName: user.display_name,
    roles: roleRow?.roles ? String(roleRow.roles).split(',') : [],
    mustChangePassword: user.m === true || Number(user.m) === 1,
  };
}

async function recordLoginAttempt(db: Database, email: string, ip: string | undefined, success: boolean, reason?: string): Promise<void> {
  await db.transaction(async (tx) => {
    if (ip) {
      const blocked = await tx.prepare(`SELECT 1 FROM ip_blocklist
        WHERE ip = ? AND (expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now'))`).get(ip);
      if (blocked) throw new Error('ip is blocked');
    }
    await tx.prepare('INSERT INTO login_attempts (email, ip, success, reason) VALUES (?, ?, ?, ?)')
      .run(email, ip ?? null, success ? 1 : 0, reason ?? null);
    if (success) {
      await tx.prepare(`UPDATE users SET failed_login_count = 0, locked_until = NULL,
        last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), last_login_ip = ? WHERE email = ?`).run(ip ?? null, email);
    } else {
      await tx.prepare(`UPDATE users SET failed_login_count = failed_login_count + 1,
        locked_until = CASE WHEN failed_login_count + 1 >= 5
          THEN strftime('%Y-%m-%dT%H:%M:%fZ','now','+15 minutes') ELSE locked_until END
        WHERE email = ?`).run(email);
      if (ip) {
        const recent = await tx.prepare(`SELECT count(*) AS n FROM login_attempts
          WHERE ip = ? AND success = 0 AND created_at > strftime('%Y-%m-%dT%H:%M:%fZ','now','-10 minutes')`).get(ip);
        if (Number(recent?.n ?? 0) >= 20) {
          await tx.prepare(`INSERT INTO ip_blocklist (ip, reason, expires_at)
            VALUES (?, 'auto: 20 failed logins in 10 minutes',
              strftime('%Y-%m-%dT%H:%M:%fZ','now','+1 hour'))
            ON CONFLICT (ip) DO NOTHING`).run(ip);
        }
      }
    }
  });
}

async function startSession(db: Database, userId: number, remember: boolean, ip?: string, ua?: string) {
  const token = randomBytes(32).toString('base64url');
  const maxAgeSec = remember ? 365 * 86400 : 86400;
  await db.transaction(async (tx) => {
    const active = await tx.prepare("SELECT 1 FROM users WHERE id = ? AND status = 'active'").get(userId);
    if (!active) throw new Error('account is not active');
    await tx.prepare('INSERT INTO sessions (id, user_id, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?)')
      .run(sha(token), userId, new Date(Date.now() + maxAgeSec * 1000).toISOString(), ip ?? null, (ua ?? '').slice(0, 300) || null);
    await tx.prepare(`WITH old_sessions AS (
      SELECT id FROM sessions WHERE user_id = ? AND revoked_at IS NULL
      ORDER BY created_at DESC, id DESC OFFSET 10
    )
    UPDATE sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE id IN (SELECT id FROM old_sessions)`).run(userId);
  });
  return { token, maxAgeSec };
}

export async function login(db: Database, o: { email: string; password: string; remember?: boolean; ip?: string; ua?: string }): Promise<LoginResult> {
  const email = String(o.email ?? '').trim().slice(0, 254);
  const password = String(o.password ?? '').slice(0, 1024);
  if (!email || !password) return { ok: false, code: 'invalid' };
  try {
    if (DEV_MODE && await db.prepare('SELECT 1 FROM recovery_accounts WHERE email = ?').get(email)) {
      const recovered = await recoverOwner(db, email, password, o.ip);
      if (!recovered) return { ok: false, code: 'invalid' };
      const user = await userById(db, recovered.userId);
      if (!user) return { ok: false, code: 'invalid' };
      return {
        ok: true,
        ...(await startSession(db, recovered.userId, false, o.ip, o.ua)),
        user,
        restored: recovered.restored === 'none' ? undefined : recovered.restored,
      };
    }
    const user = await db.prepare('SELECT id, password_hash, status, locked_until FROM users WHERE email = ?').get(email);
    const locked = !!user?.locked_until && user.locked_until > new Date().toISOString();
    const good = verifyPassword(password, user?.password_hash ?? DUMMY_HASH) && !!user?.password_hash;
    if (user && good && user.status === 'pending') return { ok: false, code: 'pending' };
    if (!user || user.status !== 'active' || locked || !good) {
      await recordLoginAttempt(db, email, o.ip, false, locked ? 'locked' : 'bad_credentials');
      return { ok: false, code: locked ? 'locked' : 'invalid' };
    }
    await recordLoginAttempt(db, email, o.ip, true);
    const id = Number(user.id);
    const session = await startSession(db, id, !!o.remember, o.ip, o.ua);
    const sessionUser = await userById(db, id);
    return sessionUser ? { ok: true, ...session, user: sessionUser } : { ok: false, code: 'invalid' };
  } catch (error) {
    if ((error as Error).message === 'ip is blocked') return { ok: false, code: 'blocked' };
    throw error;
  }
}

export async function loginAs(db: Database, userId: number, o: { method: string; ip?: string; ua?: string }): Promise<LoginResult> {
  const user = await db.prepare('SELECT email, status, locked_until FROM users WHERE id = ?').get(userId);
  if (!user || user.status !== 'active') return { ok: false, code: 'invalid' };
  if (user.locked_until && user.locked_until > new Date().toISOString()) return { ok: false, code: 'locked' };
  try {
    await recordLoginAttempt(db, user.email, o.ip, true, o.method);
  } catch (error) {
    if ((error as Error).message === 'ip is blocked') return { ok: false, code: 'blocked' };
    throw error;
  }
  const session = await startSession(db, userId, true, o.ip, o.ua);
  const sessionUser = await userById(db, userId);
  return sessionUser ? { ok: true, ...session, user: sessionUser } : { ok: false, code: 'invalid' };
}

export async function getSession(db: Database, token: string | undefined): Promise<SessionUser | null> {
  if (!token || token.length > 100) return null;
  const hash = sha(token);
  const session = await db.prepare(`SELECT user_id FROM sessions
    WHERE id = ? AND revoked_at IS NULL AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')`).get(hash);
  if (!session) return null;
  // Keep a remembered session alive for a full year while it is being used.
  await db.prepare("UPDATE sessions SET last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), expires_at = CASE WHEN expires_at < strftime('%Y-%m-%dT%H:%M:%fZ','now','+30 days') THEN strftime('%Y-%m-%dT%H:%M:%fZ','now','+365 days') ELSE expires_at END WHERE id = ?").run(hash);
  return userById(db, Number(session.user_id));
}

export async function logout(db: Database, token: string | undefined): Promise<void> {
  if (token) {
    await db.prepare("UPDATE sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ? AND revoked_at IS NULL").run(sha(token));
  }
}
