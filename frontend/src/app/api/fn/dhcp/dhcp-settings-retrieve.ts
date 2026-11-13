/* eslint-disable */
import { HttpClient, HttpContext, HttpResponse } from '@angular/common/http';
import { Observable } from 'rxjs';
import { filter, map } from 'rxjs/operators';
import { StrictHttpResponse } from '../../strict-http-response';
import { RequestBuilder } from '../../request-builder';

import { DhcpSettings } from '../../models/dhcp-settings';

export interface DhcpSettingsRetrieve$Params {}

export function dhcpSettingsRetrieve(http: HttpClient, rootUrl: string, params?: DhcpSettingsRetrieve$Params, context?: HttpContext): Observable<StrictHttpResponse<DhcpSettings>> {
  const rb = new RequestBuilder(rootUrl, dhcpSettingsRetrieve.PATH, 'get');
  return http.request(
    rb.build({ responseType: 'json', accept: 'application/json', context })
  ).pipe(
    filter((r: any): r is HttpResponse<any> => r instanceof HttpResponse),
    map((r: HttpResponse<any>) => {
      return r as StrictHttpResponse<DhcpSettings>;
    })
  );
}

dhcpSettingsRetrieve.PATH = '/api/dhcp/settings/';
