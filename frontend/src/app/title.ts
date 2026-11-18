import { Injectable, inject } from '@angular/core';
import { Title } from '@angular/platform-browser';
import { RouterStateSnapshot, TitleStrategy } from '@angular/router';

/** "<page> – Zones.dns" in the browser tab: tabs and history entries can be told apart. */
@Injectable()
export class PageTitle extends TitleStrategy {
  private title = inject(Title);
  override updateTitle(state: RouterStateSnapshot) {
    const t = this.buildTitle(state);
    this.title.setTitle(t ? `${t} – Zones.dns` : 'Zones.dns');
  }
}
