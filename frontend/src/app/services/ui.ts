import { Injectable, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { Auth } from './auth';
import { errorText } from '../lib/error-text';

export interface Notice { kind: 'ok' | 'error'; text: string; undo?: () => unknown }

/** Shared notices (errors and confirmations, shown by the shell above any open dialog) and the confirm dialog. */
@Injectable({ providedIn: 'root' })
export class Ui {
  private auth = inject(Auth);
  private router = inject(Router);
  private timer?: ReturnType<typeof setTimeout>;

  error = signal('');
  notice = signal<Notice | null>(null);
  box = signal<{ title: string; text: string; verb: string; ok: () => unknown } | null>(null);
  dlg?: HTMLDialogElement; // registered by the shell

  /** Ask before an action. verb names it on the button ("Delete record"), so the user sees what Confirm does. */
  ask(title: string, text: string, ok: () => unknown, verb = 'Confirm') {
    this.box.set({ title, text, verb, ok });
    this.dlg?.showModal();
  }
  yes() { const b = this.box(); this.dlg?.close(); b?.ok(); }

  /** A short confirmation ("Saved www.corp.lan"), optionally with Undo; it goes away by itself. */
  toast(text: string, undo?: () => unknown) {
    this.show({ kind: 'ok', text, undo }, undo ? 10000 : 5000);
  }
  dismiss() { clearTimeout(this.timer); this.notice.set(null); this.error.set(''); }
  async undo() {
    const u = this.notice()?.undo;
    this.dismiss();
    if (u) await this.run(async () => { await u(); });
  }

  /** Runs an API call; surfaces DRF errors; on 401 the interceptor (auth.ts) goes back to login. ok: the confirmation to show when it worked.
   * silent: a background refresh (live log, polling): it neither clears nor shows errors the user has not read yet. */
  async run(f: () => Promise<unknown>, opts: { ok?: string; silent?: boolean } = {}) {
    try {
      await f();
      if (!opts.silent) this.error.set('');
      if (opts.ok) this.toast(opts.ok);
      else if (!opts.silent && this.notice()?.kind === 'error') this.dismiss();
    } catch (e: any) {
      if (e.status === 401) return; // the interceptor already ended the session and went to the login
      if (opts.silent) return;
      const text = errorText(e);
      this.error.set(text);
      this.show({ kind: 'error', text }, 0);
    }
  }

  private show(n: Notice, ms: number) {
    clearTimeout(this.timer);
    this.notice.set(n);
    if (ms) this.timer = setTimeout(() => { if (this.notice() === n) this.notice.set(null); }, ms);
  }
}

/** Saves text as a file through the browser's download. */
export function saveFile(text: string, name: string, type: string) {
  const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([text], { type })), download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href)); // revoked at once, some browsers drop the download
}
