import { ApplicationConfig, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideHttpClient, withInterceptors, withXsrfConfiguration } from '@angular/common/http';
import { TitleStrategy, provideRouter, withComponentInputBinding } from '@angular/router';
import { PageTitle } from './title';
import { unauthorizedInterceptor } from './services/auth';
import { routes } from './app.routes';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideRouter(routes, withComponentInputBinding()),
    { provide: TitleStrategy, useClass: PageTitle },
    provideHttpClient(withInterceptors([unauthorizedInterceptor]), withXsrfConfiguration({ cookieName: 'csrftoken', headerName: 'X-CSRFToken' })), // Django's CSRF check, needed with the token cookie
  ],
};
