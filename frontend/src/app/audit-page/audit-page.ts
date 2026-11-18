import { Component, ElementRef, computed, effect, inject, input, signal, untracked, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DecimalPipe } from '@angular/common';
import { Router } from '@angular/router';
import { Api } from '../api/api';
import { auditCreate } from '../api/functions';
import { AuditReport, Finding } from '../api/models';
import { Ui } from '../services/ui';

const SEV_LABEL: { [s: string]: string } = { bad: 'Problem', warn: 'Warning', info: 'Note', ok: 'Passed' };
const SEV_RANK: { [s: string]: number } = { bad: 0, warn: 1, info: 2, ok: 3 };

@Component({
  selector: 'app-audit-page',
  imports: [FormsModule, DecimalPipe],
  templateUrl: './audit-page.html',
})
export class AuditPage {
  domain = input<string>(); // ?domain=... query parameter
  private api = inject(Api);
  private ui = inject(Ui);
  private router = inject(Router);

  sevs = ['bad', 'warn', 'info', 'ok'] as const;
  label = SEV_LABEL;
  plural: { [s: string]: string } = { bad: 'Problems', warn: 'Warnings', info: 'Notes', ok: 'Passed' };
  name = '';
  deep = false;
  busy = signal(false);
  shown = signal<Finding | null>(null);
  copied = signal(false);
  private out = viewChild.required<ElementRef<HTMLDialogElement>>('out');
  report = signal<AuditReport | null>(null);
  hidePassed = signal(true); // the OK checks fold away: what needs attention comes first
  only = signal<string | null>(null); // a summary tile picked: only that severity
  status = signal(''); // read out by screen readers when a run starts and ends
  private last?: string; // last ?domain= value handled

  constructor() {
    // Run when ?domain= changes (deep link, or the Audit button in the query log), not on every state change.
    effect(() => {
      const d = this.domain();
      untracked(() => {
        if (d && d !== this.last) { this.last = d; this.name = d; this.run(); }
      });
    });
  }

  /** Findings grouped by category, worst category first and worst finding first; filtered by the tiles and "hide passed checks". */
  categories = computed(() => {
    const only = this.only(), hide = this.hidePassed();
    const shown = (f: Finding) => (only ? f.severity === only : !(hide && f.severity === 'ok'));
    const map = new Map<string, Finding[]>();
    for (const f of this.report()?.findings ?? []) if (shown(f)) map.set(f.category, [...(map.get(f.category) ?? []), f]);
    const rank = (f: Finding) => SEV_RANK[f.severity] ?? 9;
    const worst = (l: Finding[]) => Math.min(...l.map(rank));
    return [...map].map(([name, items]) => ({ name, items: [...items].sort((a, b) => rank(a) - rank(b)) })).sort((a, b) => worst(a.items) - worst(b.items));
  });
  pick(s: string) { this.only.set(this.only() === s ? null : s); }

  openOutput(f: Finding) {
    this.shown.set(f);
    this.copied.set(false);
    this.out().nativeElement.showModal();
  }

  async copy() {
    const text = this.shown()?.output ?? '';
    try { await navigator.clipboard.writeText(text); } // only available on HTTPS / localhost
    catch {
      const ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
    }
    this.copied.set(true);
    setTimeout(() => this.copied.set(false), 1500);
  }

  keys(o: { [k: string]: string }) { return Object.keys(o); }
  secs(ms: number) { return (ms / 1000).toFixed(1); }
  years(days: number) { return days >= 365 ? `${Math.floor(days / 365)} years and ${Math.floor((days % 365) / 30)} months ago` : `${days} days ago`; }
  allLabel(q: string | null) { return ({ '-': '-all: reject everything else', '~': '~all: treat everything else as suspicious', '?': '?all: neutral', '+': '+all: accept everything' } as { [k: string]: string })[q ?? ''] ?? 'none'; }

  /** Linked services grouped by category, in a stable order. */
  serviceGroups() {
    const order = ['Hosting', 'Web', 'DNS', 'Mail', 'Outbound mail', 'Linked services'];
    const map = new Map<string, { name: string; evidence: string }[]>();
    for (const s of this.report()?.services ?? []) map.set(s.category, [...(map.get(s.category) ?? []), s]);
    return [...map].map(([cat, items]) => ({ cat, items })).sort((a, b) => order.indexOf(a.cat) - order.indexOf(b.cat));
  }
  date(iso: string | null | undefined, time = false) {
    if (!iso) return '—';
    const d = new Date(iso);
    return time ? d.toLocaleString() : d.toLocaleDateString();
  }

  async run() {
    const domain = this.name.trim();
    if (!domain || this.busy()) return;
    this.busy.set(true);
    this.report.set(null); this.only.set(null);
    this.status.set(`Analysing ${domain}…`);
    await this.ui.run(async () => {
      const r = await this.api.invoke(auditCreate, { body: { domain, deep: this.deep } });
      this.report.set(r);
      const n = (s: string, one: string, many: string) => `${r.summary[s as keyof typeof r.summary]} ${r.summary[s as keyof typeof r.summary] === 1 ? one : many}`;
      this.status.set(`Analysis of ${r.domain} finished: ${n('bad', 'problem', 'problems')}, ${n('warn', 'warning', 'warnings')}, ${n('ok', 'check passed', 'checks passed')}.`);
      this.last = r.domain; // the URL update below must not trigger another run
      this.router.navigate([], { queryParams: { domain: r.domain }, replaceUrl: true });
    });
    this.busy.set(false);
    if (!this.report()) this.status.set('');
  }
}
