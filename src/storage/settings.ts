import type { DatabaseSync } from 'node:sqlite';

/** Instance-wide settings (table app_settings). Changed by the operator through the farcmd-admin CLI. */
export class SqliteSettingsStore {
  constructor(private readonly db:DatabaseSync){}
  get(key:string):string|undefined{ return (this.db.prepare('SELECT value FROM app_settings WHERE key=?').get(key) as any)?.value; }
  set(key:string,value:string):void{ this.db.prepare('INSERT INTO app_settings (key,value,updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at').run(key,value,Date.now()); }
  /** Self-service registration in the web UI. Off unless explicitly enabled. */
  registrationEnabled():boolean{ return this.get('registration_enabled')==='true'; }
  setRegistrationEnabled(enabled:boolean):void{ this.set('registration_enabled',enabled?'true':'false'); }
}
