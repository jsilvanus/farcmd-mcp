import { randomToken } from './oauth/pkce.js';
import type { WebSessionStore } from './storage/interface.js';

export class WebSessionService {
  constructor(private readonly store: WebSessionStore) {}

  create(userId:string): string {
    const token=randomToken();
    this.store.saveWebSession({token,userId,expires:Date.now()+7*24*60*60_000});
    return token;
  }

  get(token:string) {
    const session=this.store.getWebSession(token);
    if (!session || session.expires < Date.now()) {
      if (session) this.store.deleteWebSession(token);
      return undefined;
    }
    return session;
  }

  delete(token:string): void { this.store.deleteWebSession(token); }
}
