import { Component, computed, input } from '@angular/core';
import { DaemonStatus } from '../api/models';

/** Whether a daemon (rundhcp, runproxy) runs: an LED and the words, from its heartbeat (GET /api/status/). */
@Component({
  selector: 'app-daemon-status',
  template: `
    <p class="daemon-st" role="status">
      @if (d(); as d) {
        <span class="led" [attr.data-s]="led()" aria-hidden="true"></span>
        @if (!d.enabled) { {{ name() }}: off in the settings@if (d.running) {; <code>{{ d.command }}</code> runs and waits until it is turned on}. }
        @else if (d.running) { {{ name() }}: running. }
        @else { {{ name() }}: not running. Start <code>manage.py {{ d.command }}</code>@if (d.last_seen) {; last seen {{ seen(d.last_seen) }}}. }
      } @else { <span class="led" aria-hidden="true"></span> {{ name() }}: checking… }
    </p>`,
})
export class DaemonStatusLine {
  d = input<DaemonStatus | undefined>();
  name = input.required<string>(); // "DHCP server"
  led = computed(() => { const d = this.d(); return !d?.enabled ? 'off' : d.running ? 'ok' : 'bad'; });
  seen(iso: string) {
    const t = new Date(iso);
    return t.toDateString() === new Date().toDateString() ? t.toLocaleTimeString() : t.toLocaleString();
  }
}
