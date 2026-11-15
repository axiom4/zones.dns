import { Component, ElementRef, computed, inject, signal, viewChild } from '@angular/core';
import { Ping } from '../services/ping';

/** A window that pings one host every second and prints what `ping` prints (iputils format), until Stop or Close. */
@Component({
  selector: 'app-ping-live',
  templateUrl: './ping-live.html',
})
export class PingLive {
  private ping = inject(Ping);
  private dlg = viewChild.required<ElementRef<HTMLDialogElement>>('dlg');
  private out = viewChild<ElementRef<HTMLTextAreaElement>>('out');
  address = signal('');
  lines = signal<string[]>([]);
  running = signal(false);
  copied = signal(false);
  text = computed(() => this.lines().join('\n'));
  private run = 0; // a new window (or a close) ends the loop of the old one
  private times: number[] = [];
  private sent = 0;
  private started = 0;

  open(address: string) {
    this.address.set(address);
    this.dlg().nativeElement.showModal();
    this.start();
  }
  start() {
    const address = this.address();
    this.times = []; this.sent = 0; this.started = Date.now(); this.copied.set(false);
    this.lines.set([`PING ${address} (${address}) 56(84) bytes of data.`]);
    this.running.set(true);
    this.loop(address, ++this.run);
  }
  /** Like Ctrl-C: the loop ends and the statistics are printed. */
  stop() {
    if (!this.running()) return;
    this.run++;
    this.running.set(false);
    this.add(...this.statistics());
  }
  async copy() {
    try { await navigator.clipboard.writeText(this.text()); this.copied.set(true); } catch { this.out()?.nativeElement.select(); }
  }

  private statistics() {
    const a = this.address(), got = this.times.length;
    const loss = this.sent ? Math.round(100 * (this.sent - got) / this.sent) : 0;
    const lines = ['', `--- ${a} ping statistics ---`, `${this.sent} packets transmitted, ${got} received, ${loss}% packet loss, time ${Date.now() - this.started}ms`];
    if (got) {
      const min = Math.min(...this.times), max = Math.max(...this.times), avg = this.times.reduce((x, y) => x + y, 0) / got;
      const mdev = Math.sqrt(this.times.reduce((x, y) => x + (y - avg) ** 2, 0) / got);
      lines.push(`rtt min/avg/max/mdev = ${[min, avg, max, mdev].map(v => v.toFixed(3)).join('/')} ms`);
    }
    return lines;
  }
  private add(...more: string[]) {
    this.lines.update(l => [...l, ...more].slice(-3600));
    setTimeout(() => { const t = this.out()?.nativeElement; if (t) t.scrollTop = t.scrollHeight; });
  }
  private async loop(address: string, id: number) {
    for (let seq = 1; id === this.run; seq++) {
      const began = Date.now();
      this.sent++;
      try {
        const r = await this.ping.once(address);
        if (id !== this.run) return;
        if (r.error) { this.sent--; this.add(`ping: ${r.error}`); this.run++; this.running.set(false); return; } // refused for good: asking again changes nothing
        if (r.up) {
          this.times.push(r.ms ?? 0);
          this.add(`${r.bytes ?? 64} bytes from ${address}: icmp_seq=${seq}${r.ttl != null ? ` ttl=${r.ttl}` : ''} time=${(r.ms ?? 0).toFixed(2)} ms`);
        } else this.add(`no answer yet for icmp_seq=${seq}`);
      } catch (e: any) {
        if (id !== this.run) return;
        this.sent--;
        this.add(`ping: ${e.error?.detail ?? e.message ?? 'request failed'}`);
        this.run++; this.running.set(false);
        return;
      }
      await new Promise(r => setTimeout(r, Math.max(0, 1000 - (Date.now() - began))));
    }
  }
}
