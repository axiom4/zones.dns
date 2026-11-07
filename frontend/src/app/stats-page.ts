import { DecimalPipe } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from './api/api';
import { blockedCreate, statsRetrieve } from './api/functions';
import { Stats } from './api/models';
import { Ui } from './ui';

@Component({
  selector: 'app-stats-page',
  imports: [FormsModule, DecimalPipe],
  template: `
    @if (stats(); as st) {
      <header>
        <div>
          <h2>Statistics</h2>
          <p class="soft">Queries received by the DNS daemon.</p>
        </div>
        <div class="actions">
          <select [(ngModel)]="hours" name="h" (ngModelChange)="load()" aria-label="Period">
            <option [ngValue]="1">Last hour</option>
            <option [ngValue]="24">Last 24 hours</option>
            <option [ngValue]="168">Last 7 days</option>
            <option [ngValue]="720">Last 30 days</option>
          </select>
          <button class="ghost" (click)="load()">Refresh</button>
        </div>
      </header>

      <div class="tiles">
        <div class="tile"><b>{{ st.total }}</b><span>Query</span></div>
        <div class="tile"><b>{{ outcome('local') }}</b><span>From internal zones</span></div>
        <div class="tile"><b>{{ outcome('forwarded') }}</b><span>Forwarded</span></div>
        <div class="tile warn"><b>{{ outcome('blocked') }}</b><span>Blocked</span></div>
        <div class="tile"><b>{{ st.avg_ms | number: '1.0-0' }} ms</b><span>Average time</span></div>
      </div>

      <section class="panel">
        <h3>Queries per hour</h3>
        @if (st.per_hour.length) {
          <div class="chart" [class.dense]="st.per_hour.length > 30">
            @for (p of st.per_hour; track p.hour) {
              <div class="col" [title]="hourLabel(p.hour) + ': ' + p.count" [style.--h]="pct(p.count, st.per_hour) + '%'">
                <b>{{ p.count }}</b>
                <i [style.height.%]="pct(p.count, st.per_hour)"></i>
                <span>{{ hh(p.hour) }}</span>
              </div>
            }
          </div>
        } @else { <p class="soft">No queries in this period.</p> }
      </section>

      <div class="grid2">
        <section class="panel">
          <h3>Most requested domains</h3>
          @for (d of st.top_domains; track d.name) {
            <div class="row">
              <span class="bar" [style.width.%]="pct(d.count, st.top_domains)"></span>
              <span class="n">{{ d.name }}</span><span class="c">{{ d.count }}</span>
              @if (done().has(d.name)) { <span class="soft">Blocked</span> }
              @else { <button class="mini" (click)="block(d.name)" [attr.aria-label]="'Block ' + d.name">Block</button> }
            </div>
          } @empty { <p class="soft">No data.</p> }
        </section>
        <section class="panel">
          <h3>Most requested blocked domains</h3>
          @for (d of st.top_blocked; track d.name) {
            <div class="row"><span class="bar warn" [style.width.%]="pct(d.count, st.top_blocked)"></span><span class="n">{{ d.name }}</span><span class="c">{{ d.count }}</span></div>
          } @empty { <p class="soft">No blocked queries.</p> }
        </section>
        <section class="panel">
          <h3>Most active clients</h3>
          @for (d of st.top_clients; track d.name) {
            <div class="row"><span class="bar" [style.width.%]="pct(d.count, st.top_clients)"></span><span class="n">{{ d.name }}</span><span class="c">{{ d.count }}</span></div>
          } @empty { <p class="soft">No data.</p> }
        </section>
        <section class="panel">
          <h3>Query types</h3>
          @for (d of st.by_type; track d.name) {
            <div class="row"><span class="bar" [style.width.%]="pct(d.count, st.by_type)"></span><span class="n">{{ d.name }}</span><span class="c">{{ d.count }}</span></div>
          } @empty { <p class="soft">No data.</p> }
        </section>
      </div>
    }`,
})
export class StatsPage {
  private api = inject(Api);
  private ui = inject(Ui);
  stats = signal<Stats | null>(null);
  done = signal(new Set<string>());
  hours = 24;

  constructor() { this.load(); }

  load() { return this.ui.run(async () => this.stats.set(await this.api.invoke(statsRetrieve, { hours: this.hours }))); }
  block(name: string) {
    return this.ui.run(async () => {
      await this.api.invoke(blockedCreate, { body: { name } });
      this.done.update(s => new Set(s).add(name));
    });
  }
  outcome(name: string) { return this.stats()?.by_outcome.find(c => c.name === name)?.count ?? 0; }
  pct(c: number, list: { count: number }[]) { return Math.round((c / Math.max(...list.map(x => x.count), 1)) * 100); }
  hh(iso: string) { return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
  hourLabel(iso: string) { return new Date(iso).toLocaleString([], { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }); }
}
