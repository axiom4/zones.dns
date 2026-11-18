import { AfterViewInit, Directive, ElementRef, OnDestroy, inject, output } from '@angular/core';

/**
 * Infinite scroll: `<div (appInView)="more()"></div>` at the end of a list fires when it comes within 400 px of the viewport.
 * It fires once per element, so the template makes a new one after each load (`@for (n of [rows().length]; track n)`): the new element is
 * observed afresh and fires again if the end of the list is still on screen. Without IntersectionObserver nothing fires: the buttons stay.
 */
@Directive({ selector: '[appInView]', host: { 'aria-hidden': 'true' } })
export class InView implements AfterViewInit, OnDestroy {
  appInView = output<void>();
  private el = inject<ElementRef<HTMLElement>>(ElementRef);
  private io?: IntersectionObserver;

  ngAfterViewInit() {
    if (typeof IntersectionObserver === 'undefined') return;
    this.io = new IntersectionObserver(es => {
      if (es.some(e => e.isIntersecting)) { this.io?.disconnect(); this.appInView.emit(); }
    }, { rootMargin: '400px' });
    this.io.observe(this.el.nativeElement);
  }

  ngOnDestroy() { this.io?.disconnect(); }
}
