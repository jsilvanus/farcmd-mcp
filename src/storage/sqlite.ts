import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type {
  AuthStore,
  AuthorizationCodeRecord,
  McpUser,
  RefreshTokenRecord,
  UserStore,
  WebSessionRecord,
  WebSessionStore,
} from './interface.js';

export class SqliteAuthStore implements AuthStore, WebSessionStore {
  private readonly db: DatabaseSync;

  constructor(path: string) {
    mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec(
      'CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE, password_hash TEXT, created_at INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS authorization_codes (code TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, subject TEXT NOT NULL, scope TEXT NOT NULL, expires INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS refresh_tokens (token TEXT PRIMARY KEY, client_id TEXT NOT NULL, subject TEXT NOT NULL, scope TEXT NOT NULL, expires INTEGER NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS web_sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires INTEGER NOT NULL);'
    );
  }

  getDatabase(): DatabaseSync { return this.db; }

  saveAuthorizationCode(record: AuthorizationCodeRecord): void {
    this.db.prepare(
      'INSERT INTO authorization_codes (code, client_id, redirect_uri, challenge, subject, scope, expires) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(record.code, record.clientId, record.redirectUri, record.challenge, record.subject, record.scope, record.expires);
  }

  consumeAuthorizationCode(code: string): AuthorizationCodeRecord | undefined {
    const row = this.db.prepare(
      'SELECT code, client_id, redirect_uri, challenge, subject, scope, expires FROM authorization_codes WHERE code = ?'
    ).get(code) as {code:string;client_id:string;redirect_uri:string;challenge:string;subject:string;scope:string;expires:number}|undefined;
    if (!row || row.expires < Date.now()) {
      this.db.prepare('DELETE FROM authorization_codes WHERE code = ?').run(code);
      return undefined;
    }
    this.db.prepare('DELETE FROM authorization_codes WHERE code = ?').run(code);
    return {
      code: row.code, clientId: row.client_id, redirectUri: row.redirect_uri,
      challenge: row.challenge, subject: row.subject, scope: row.scope, expires: row.expires,
    };
  }

  saveRefreshToken(record: RefreshTokenRecord): void {
    this.db.prepare(
      'INSERT INTO refresh_tokens (token, client_id, subject, scope, expires) VALUES (?, ?, ?, ?, ?)'
    ).run(record.token, record.clientId, record.subject, record.scope, record.expires);
  }

  saveWebSession(record: WebSessionRecord): void {
    this.db.prepare('INSERT INTO web_sessions (token, user_id, expires) VALUES (?, ?, ?)').run(record.token, record.userId, record.expires);
  }

  getWebSession(token: string): WebSessionRecord | undefined {
    const row=this.db.prepare('SELECT token,user_id,expires FROM web_sessions WHERE token=?').get(token) as {token:string;user_id:string;expires:number}|undefined;
    return row ? {token:row.token,userId:row.user_id,expires:row.expires} : undefined;
  }

  deleteWebSession(token: string): void {
    this.db.prepare('DELETE FROM web_sessions WHERE token=?').run(token);
  }

  getRefreshToken(token: string): RefreshTokenRecord | undefined {
    const row = this.db.prepare(
      'SELECT token, client_id, subject, scope, expires FROM refresh_tokens WHERE token = ?'
    ).get(token) as {token:string;client_id:string;subject:string;scope:string;expires:number}|undefined;
    if (!row || row.expires < Date.now()) {
      if (row) this.db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(token);
      return undefined;
    }
    return {
      token: row.token, clientId: row.client_id, subject: row.subject,
      scope: row.scope, expires: row.expires,
    };
  }
}

export class SqliteUserStore implements UserStore {
  constructor(private readonly db: DatabaseSync) {}

  createUser(user: McpUser): void {
    this.db.prepare(
      'INSERT INTO users (id, name, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(user.id, user.name, user.email ?? null, user.passwordHash ?? null, user.createdAt);
  }

  listUsers(): McpUser[] {
    const rows = this.db.prepare(
      'SELECT id, name, email, password_hash, created_at FROM users ORDER BY name, id'
    ).all() as Array<{id:string;name:string;email:string|null;password_hash:string|null;created_at:number}>;
    return rows.map(this.map);
  }

  getUser(id: string): McpUser | undefined {
    return this.map(this.db.prepare(
      'SELECT id, name, email, password_hash, created_at FROM users WHERE id = ?'
    ).get(id) as {id:string;name:string;email:string|null;password_hash:string|null;created_at:number}|undefined);
  }

  updateUser(id:string,name:string,email:string): void {
    this.db.prepare('UPDATE users SET name=?, email=? WHERE id=?').run(name,email,id);
  }

  getUserByEmail(email: string): McpUser | undefined {
    return this.map(this.db.prepare(
      'SELECT id, name, email, password_hash, created_at FROM users WHERE lower(email) = lower(?)'
    ).get(email) as {id:string;name:string;email:string|null;password_hash:string|null;created_at:number}|undefined);
  }

  private map = (row: {id:string;name:string;email:string|null;password_hash:string|null;created_at:number}|undefined): McpUser|undefined =>
    row ? {
      id: row.id, name: row.name,
      ...(row.email ? {email: row.email} : {}),
      ...(row.password_hash ? {passwordHash: row.password_hash} : {}),
      createdAt: row.created_at,
    } : undefined;
}
