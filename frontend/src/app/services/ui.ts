import { Injectable, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { Auth } from './auth';
import { errorText } from '../lib/error-text';

/** Shared error banner and confirm dialog. */
@Injectable({ providedIn: 'root' })
export class Ui {
  private auth = inject(Auth);
  private router = inject(Router);

  error = signal('');
  box = signal<{ title: string; text: string; ok: () => unknown } | null>(null);
  dlg?: HTMLDialogElement; // registered by the shell

  ask(title: string, text: string, ok: () => unknown) {
    this.box.set({ title, text, ok });
    this.dlg?.showModal();
  }
  yes() { const b = this.box(); this.dlg?.close(); b?.ok(); }

  // Runs an API call; surfaces DRF validation errors ({field: [msg]}); on 401 goes back to login.
  async run(f: () => Promise<unknown>) {
    try { await f(); this.error.set(''); }
    catch (e: any) {
      if (e.status === 401) { this.auth.logout(); this.router.navigateByUrl('/login'); }
      this.error.set(errorText(e));
    }
  }
}

/** Saves text as a file through the browser's download. */
export function saveFile(text: string, name: string, type: string) {
  const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([text], { type })), download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href)); // revoked at once, some browsers drop the download
}
