import { TypeEnum } from '../api/models';

export interface Field {
  key: string;
  label: string;
  help: string;
  placeholder?: string;
  kind?: 'text' | 'number' | 'select' | 'textarea';
  options?: { value: string; label: string }[];
  min?: number;
  max?: number;
  default?: string;
  optional?: boolean;
  quoted?: boolean; // written between double quotes in the zone file
  rest?: boolean; // swallows all remaining tokens (last field only)
  pattern?: RegExp;
  patternMsg?: string;
}

export interface TypeSpec {
  type: TypeEnum;
  title: string;
  group: string;
  about: string;
  example: string;
  fields: Field[];
}

const host = (key: string, label: string, help: string, placeholder = 'server.corp.lan.'): Field =>
  ({ key, label, help, placeholder });
const num = (key: string, label: string, help: string, def: string, min = 0, max = 65535): Field =>
  ({ key, label, help, kind: 'number', default: def, min, max });
const sel = (key: string, label: string, help: string, options: [string, string][], def: string): Field =>
  ({ key, label, help, kind: 'select', default: def, options: options.map(([value, label]) => ({ value, label })) });
const HEX = /^[0-9a-fA-F]+$/;

export const TYPE_SPECS: TypeSpec[] = [
  { type: 'A', title: 'IPv4 address', group: 'Addresses and aliases',
    about: 'Links a name to an IPv4 address. It is the most common record: it lets you reach a server or device by name.',
    example: 'nas → 10.0.0.20',
    fields: [{ key: 'ip', label: 'IPv4 address', help: 'The device address: four numbers from 0 to 255 separated by dots.', placeholder: '10.0.0.20',
      pattern: /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/, patternMsg: 'Invalid IPv4 address (e.g. 10.0.0.20).' }] },
  { type: 'AAAA', title: 'IPv6 address', group: 'Addresses and aliases',
    about: 'Like the A record, but for an IPv6 address. You can have both A and AAAA for the same name.',
    example: 'nas → fd00::20',
    fields: [{ key: 'ip', label: 'IPv6 address', help: 'The address in hexadecimal with colons.', placeholder: 'fd00::20',
      pattern: /^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$/, patternMsg: 'Invalid IPv6 address (e.g. fd00::20).' }] },
  { type: 'CNAME', title: 'Alias', group: 'Addresses and aliases',
    about: 'Points one name at another. Whoever asks gets the answer of the target name, so if the address changes you only update one record.',
    example: 'wiki → server.corp.lan.',
    fields: [host('target', 'Target name', 'The name the alias points to. With a trailing dot it is a full name; without, it is relative to the zone; @ means the zone itself.')] },
  { type: 'MX', title: 'Mail server', group: 'Mail and verification',
    about: 'Says which server receives the mail for a domain. They go on the zone name (@).',
    example: '@ → 10 mail.corp.lan.',
    fields: [
      num('priority', 'Priority', 'Lower = preferred. Mail goes to the server with the lowest number; the others are backups.', '10'),
      host('target', 'Mail server', 'The server name (it must have an A or AAAA record, not an alias).', 'mail.corp.lan.'),
    ] },
  { type: 'TXT', title: 'Text', group: 'Mail and verification',
    about: 'Holds free text. Used for SPF and DMARC (mail anti-spoofing) and to prove ownership of a domain to external services.',
    example: '@ → "v=spf1 mx -all"',
    fields: [{ key: 'text', label: 'Text', kind: 'textarea', help: 'Type it without quotes: the form adds them. Beyond 255 characters it is split automatically.', placeholder: 'v=spf1 mx -all' }] },
  { type: 'NS', title: 'Name server', group: 'Network',
    about: 'Says which DNS server is authoritative for a zone or one of its sub-zones. Used to delegate a subdomain to another server.',
    example: 'sub → ns1.sub.corp.lan.',
    fields: [host('target', 'DNS server', 'The name of the DNS server you delegate to.', 'ns1.corp.lan.')] },
  { type: 'PTR', title: 'Reverse lookup', group: 'Network',
    about: 'From the address back to the name. It lives in reverse zones (in-addr.arpa) and is used by logs, SSH and mail servers.',
    example: '7 → srv.corp.lan.',
    fields: [host('target', 'Device name', 'The full name associated with this address.', 'srv.corp.lan.')] },
  { type: 'SRV', title: 'Service', group: 'Services',
    about: 'Says where a service is (host and port). The name has the form _service._protocol, for example _ldap._tcp.',
    example: '_ldap._tcp → 10 5 389 dc.corp.lan.',
    fields: [
      num('priority', 'Priority', 'Lower = tried first.', '10'),
      num('weight', 'Weight', 'Among servers with the same priority, those with a higher weight get more requests.', '5'),
      num('port', 'Port', 'The TCP/UDP port the service answers on.', '389', 0, 65535),
      host('target', 'Host', 'The server that provides the service.', 'dc.corp.lan.'),
    ] },
  { type: 'NAPTR', title: 'Name rewriting', group: 'Services',
    about: 'Mostly used in telephony (SIP, ENUM). Turns an identifier into a service using rewrite rules. If you do not know what it is, you probably do not need it.',
    example: '@ → 100 10 "S" "SIP+D2U" "" _sip._udp.corp.lan.',
    fields: [
      num('order', 'Order', 'Records with the lowest order are evaluated first.', '100'),
      num('pref', 'Preference', 'Tie-breaker between records with the same order.', '10'),
      { key: 'flags', label: 'Flag', help: 'How to continue after this record: S = look for an SRV, A = look for A/AAAA, U = the result is a URI.', placeholder: 'S', quoted: true, optional: true },
      { key: 'service', label: 'Service', help: 'The protocol offered, for example SIP+D2U.', placeholder: 'SIP+D2U', quoted: true, optional: true },
      { key: 'regexp', label: 'Rewrite expression', help: 'Optional. Substitution rule; leave it empty if you use the replacement below.', quoted: true, optional: true },
      host('replacement', 'Replacement', 'The name to look up next. Use a dot (.) if not needed.', '_sip._udp.corp.lan.'),
    ] },
  { type: 'HTTPS', title: 'Website (HTTPS)', group: 'Services',
    about: 'Gives the browser information about a site before connecting: supported protocols and alternative servers. Speeds up the connection.',
    example: '@ → 1 . alpn=h2,h3',
    fields: [
      num('priority', 'Priority', '0 = alias to another name. From 1 up = service, the lowest wins.', '1'),
      { key: 'target', label: 'Target', help: 'A dot (.) means the same name as the record.', default: '.', placeholder: '.' },
      { key: 'params', label: 'Parameters', help: 'Optional, as key=value pairs separated by spaces. Example: alpn=h2,h3', placeholder: 'alpn=h2,h3', optional: true, rest: true },
    ] },
  { type: 'CAA', title: 'Certification authority', group: 'Security',
    about: 'Lists which authorities may issue TLS certificates for the domain. Anyone not listed must refuse.',
    example: '@ → 0 issue "letsencrypt.org"',
    fields: [
      sel('flags', 'Flag', 'Leave 0, unless you want the authority to also refuse properties it does not know (128).', [['0', '0 · normal'], ['128', '128 · critical']], '0'),
      sel('tag', 'Rule type', 'issue = who may issue certificates; issuewild = who may issue wildcard certificates; iodef = where to report violations.',
        [['issue', 'issue'], ['issuewild', 'issuewild'], ['iodef', 'iodef']], 'issue'),
      { key: 'value', label: 'Value', help: 'The authority domain (letsencrypt.org) or, for iodef, a mailto: address.', placeholder: 'letsencrypt.org', quoted: true },
    ] },
  { type: 'SSHFP', title: 'SSH key fingerprint', group: 'Security',
    about: 'Publishes the fingerprint of the SSH host key, so the client can check it is talking to the right server without asking for confirmation.',
    example: 'srv → 4 2 ab12…',
    fields: [
      sel('alg', 'Key algorithm', 'The server key type: you find it in /etc/ssh/ssh_host_*_key.pub.', [['1', '1 · RSA'], ['2', '2 · DSA'], ['3', '3 · ECDSA'], ['4', '4 · Ed25519']], '4'),
      sel('fp', 'Fingerprint type', 'Hash function used. SHA-256 is the recommended choice.', [['1', '1 · SHA-1'], ['2', '2 · SHA-256']], '2'),
      { key: 'fingerprint', label: 'Fingerprint', help: 'Hexadecimal digits, obtainable with: ssh-keygen -r server-name', placeholder: 'ab12cd34…', pattern: HEX, patternMsg: 'Hexadecimal digits only (0-9, a-f).' },
    ] },
  { type: 'TLSA', title: 'Certificate association (DANE)', group: 'Security',
    about: 'Binds a TLS service to a certificate or key, so clients can verify it through DNS and not only through external authorities.',
    example: '_443._tcp → 3 1 1 ab12…',
    fields: [
      sel('usage', 'Usage', '3 = the server certificate (the most used); 2 = your own certification authority; 0/1 = pin a public CA.',
        [['0', '0 · pinned CA'], ['1', '1 · pinned certificate'], ['2', '2 · trust anchor'], ['3', '3 · server certificate']], '3'),
      sel('selector', 'What to compare', '0 = the whole certificate; 1 = only the public key (survives renewals).', [['0', '0 · whole certificate'], ['1', '1 · public key']], '1'),
      sel('matching', 'Data format', '0 = full data; 1 = SHA-256; 2 = SHA-512.', [['0', '0 · full'], ['1', '1 · SHA-256'], ['2', '2 · SHA-512']], '1'),
      { key: 'data', label: 'Data', help: 'Hexadecimal digits of the certificate or its hash.', placeholder: 'ab12cd34…', pattern: HEX, patternMsg: 'Hexadecimal digits only (0-9, a-f).' },
    ] },
];

export const SPEC = Object.fromEntries(TYPE_SPECS.map(s => [s.type, s])) as { [t: string]: TypeSpec };
export const GROUPS = [...new Set(TYPE_SPECS.map(s => s.group))].map(g => ({ name: g, specs: TYPE_SPECS.filter(s => s.group === g) }));

export const TTL_PRESETS = [
  { value: 60, label: '1 minute' }, { value: 300, label: '5 minutes' }, { value: 3600, label: '1 hour' }, { value: 86400, label: '1 day' },
];

export const TXT_TEMPLATES = [
  { label: 'SPF', text: 'v=spf1 mx -all' },
  { label: 'DMARC', text: 'v=DMARC1; p=none; rua=mailto:postmaster@corp.lan' },
];

const quote = (s: string) => `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

/** Splits RDATA into tokens, keeping quoted strings together. */
export function tokenize(s: string) {
  const out: { t: string; q: boolean }[] = [];
  const re = /"((?:[^"\\]|\\.)*)"|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) out.push(m[1] !== undefined ? { t: m[1].replace(/\\(.)/g, '$1'), q: true } : { t: m[2], q: false });
  return out;
}

/** Field values -> zone-file RDATA. */
export function compose(spec: TypeSpec, v: { [k: string]: string }): string {
  if (spec.type === 'TXT') {
    const t = v['text'] ?? '';
    return (t.match(/[\s\S]{1,255}/g) ?? ['']).map(quote).join(' ');
  }
  return spec.fields
    .map(f => (f.quoted ? quote(v[f.key] ?? '') : (v[f.key] ?? '').trim()))
    .filter((p, i) => !(spec.fields[i].optional && !spec.fields[i].quoted && p === ''))
    .join(' ');
}

/** Zone-file RDATA -> field values, or null if it doesn't fit the form (then the raw editor is used). */
export function parse(spec: TypeSpec, value: string): { [k: string]: string } | null {
  const tk = tokenize(value);
  if (spec.type === 'TXT') return { text: tk.map(x => x.t).join('') };
  const n = spec.fields.length, last = spec.fields[n - 1];
  if (last.rest ? tk.length < n - 1 : tk.length !== n) return null;
  const out: { [k: string]: string } = {};
  spec.fields.forEach((f, i) => { out[f.key] = f.rest ? tk.slice(i).map(x => x.t).join(' ') : tk[i].t; });
  return out;
}

export function defaults(spec: TypeSpec) {
  return Object.fromEntries(spec.fields.map(f => [f.key, f.default ?? '']));
}

/** First problem with a field value, or '' if fine. */
export function validate(f: Field, v: string): string {
  const x = (v ?? '').trim();
  if (!x) return f.optional ? '' : 'Required field.';
  if (f.kind === 'number') {
    const n = Number(x);
    if (!Number.isInteger(n) || n < (f.min ?? 0) || n > (f.max ?? 65535)) return `Enter a whole number between ${f.min ?? 0} and ${f.max ?? 65535}.`;
  }
  if (f.pattern && !f.pattern.test(x)) return f.patternMsg ?? 'Invalid value.';
  return '';
}
