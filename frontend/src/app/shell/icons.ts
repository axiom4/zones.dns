/** Stroke icons on a 24 px grid (drawn for this app): one path each, coloured by currentColor. */
export const ICONS = {
  zones: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18Z M3.5 9h17 M3.5 15h17 M12 3c-2.4 2.5-3.6 5.5-3.6 9s1.2 6.5 3.6 9 M12 3c2.4 2.5 3.6 5.5 3.6 9s-1.2 6.5-3.6 9',
  devices: 'M3 5.5h13v9H3z M1.5 18h16 M19 8.5h3.5V19H19z',
  blocklist: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18Z M5.7 5.7l12.6 12.6',
  logs: 'M9 6h11 M9 12h11 M9 18h11 M4.5 6h.01 M4.5 12h.01 M4.5 18h.01',
  proxy: 'M12 3l7.5 3v5.2c0 4.6-3.1 8.4-7.5 9.8-4.4-1.4-7.5-5.2-7.5-9.8V6z M9 12l2.2 2.2L15.5 10',
  stats: 'M4.5 20.5h15 M6.5 17v-5 M11 17V6.5 M15.5 17v-8 M20 17V4',
  map: 'M12 21s-6.5-5.8-6.5-11.2a6.5 6.5 0 1 1 13 0C18.5 15.2 12 21 12 21Z M12 7.3a2.5 2.5 0 1 0 0 5a2.5 2.5 0 1 0 0-5Z',
  audit: 'M10.5 3.5a7 7 0 1 0 0 14a7 7 0 1 0 0-14Z M15.6 15.6L21 21 M7.6 10.6l2 2 3.5-3.7',
  security: 'M8 16a4 4 0 1 0 0-8a4 4 0 1 0 0 8Z M12 12h9 M17.5 12v3.2 M20.5 12v2.2',
  admin: 'M14 3.5h6.5V10 M20.5 3.5L11 13 M18 14.5v6H3.5V6h6',
  signout: 'M14.5 3.5h5v17h-5 M10 7.5L5.5 12l4.5 4.5 M5.5 12h11',
  more: 'M5 12h.01 M12 12h.01 M19 12h.01',
} as const;
export type IconName = keyof typeof ICONS;
