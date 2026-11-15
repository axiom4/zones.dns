import { Component, ElementRef, computed, inject, signal, viewChild } from '@angular/core';
import { Ping } from '../services/ping';

interface Sample { n: number; up: boolean; ms: number | null; error: string }

/** A window that pings one host every second until it is closed (open it with a double click on a Ping button). */
@Component({
  selector: 'app-ping-live',
  templateUrl: './ping-live.html',
})
export class PingLive {
  private ping = inject(Ping);
  private dlg = viewChild.required<ElementRef<HTMLDialogElement>>('dlg');
  address = signal('');
  samples = signal<Sample[]>([]);
  private run = 0; // a new window (or a close) ends the loop of the old one
  shown = computed(() => [...this.samples()].reverse().slice(0, 30));
  sent = computed(() => this.samples().length);
  got = computed(() => this.samples().filter(s => s.up).length);
  times = computed(() => this.samples().filter(s => s.up && s.ms != null).map(s => s.ms as number));
  min = computed(() => this.times().length ? Math.min(...this.times()) : null);
  max = computed(() => this.times().length ? Math.max(...this.times()) : null);
  avg = computed(() => this.times().length ? Math.round(this.times().reduce((a, b) => a + b, 0) / this.times().length * 10) / 10 : null);
  loss = computed(() => this.sent() ? Math.round(100 * (this.sent() - this.got()) / this.sent()) : 0);

  open(address: string) {
    this.address.set(address);
    this.samples.set([]);
    this.dlg().nativeElement.showModal();
    this.loop(address, ++this.run);
  }
  stop() { this.run++; }

  private async loop(address: string, id: number) {
    for (let n = 1; id === this.run; n++) {
      const started = Date.now();
      let s: Sample;
      try {
        const r = await this.ping.once(address);
        s = { n, up: r.up, ms: r.ms, error: r.error };
      } catch (e: any) {
        s = { n, up: false, ms: null, error: e.error?.detail ?? e.message ?? 'Request failed.' };
        if (e.status === 401 || e.status === 403) { if (id === this.run) this.samples.update(a => [...a, s]); return; } // signed out: stop asking
      }
      if (id !== this.run) return;
      this.samples.update(a => [...a, s].slice(-3600));
      if (s.error && !s.up && s.error.startsWith('Only')) return; // refused for good: pinging again changes nothing
      await new Promise(r => setTimeout(r, Math.max(0, 1000 - (Date.now() - started))));
    }
  }
}
