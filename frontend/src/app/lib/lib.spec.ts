// Tests of the pure helpers, run by Node itself (npm test): no browser and no test framework to install.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import nacl from 'tweetnacl';
import { errorText } from './error-text.ts';
import { countryName, flag } from './geo-util.ts';
import { LoginError, seal } from './login-crypto.ts';
import { SPEC, TYPE_SPECS, compose, parse, tokenize, validate } from './record-types.ts';
import { cidrToZone, ptrToIp } from './reverse.ts';

const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');

test('cidrToZone: only whole octets, no host bits', () => {
  assert.equal(cidrToZone('10.0.0.0/24'), '0.0.10.in-addr.arpa');
  assert.equal(cidrToZone(' 192.168.0.0/16 '), '168.192.in-addr.arpa');
  assert.equal(cidrToZone('10.0.0.0/8'), '10.in-addr.arpa');
  for (const bad of ['10.0.0.1/24', '10.0.0.0/20', '300.0.0.0/8', 'fd00::/48', '']) assert.equal(cidrToZone(bad), null, bad);
});

test('ptrToIp: complete names of an IPv4 reverse zone', () => {
  assert.equal(ptrToIp('0.0.10.in-addr.arpa', '5'), '10.0.0.5');
  assert.equal(ptrToIp('168.192.in-addr.arpa', '7.1'), '192.168.1.7');
  assert.equal(ptrToIp('0.0.10.in-addr.arpa', '@'), null);
  assert.equal(ptrToIp('corp.lan', '5'), null);
});

test('flag and countryName: special codes', () => {
  assert.equal(flag('PRIV'), '🏠');
  assert.equal(flag('??'), '❔');
  assert.equal(flag('it'), '🇮🇹');
  assert.equal(countryName('PRIV'), 'Internal network');
  assert.equal(countryName('x'), 'Unknown');
  assert.equal(countryName('IT'), 'Italy');
});

test('seal: the server can read the packet and only the bound reply is accepted', () => {
  const server = nacl.box.keyPair();
  const { packet, open } = seal(b64(server.publicKey), { u: 'admin', p: 'secret' });
  const raw = Buffer.from(packet, 'base64');
  const plain = nacl.box.open(raw.subarray(56), raw.subarray(32, 56), raw.subarray(0, 32), server.secretKey);
  const body = JSON.parse(new TextDecoder().decode(plain!));
  assert.equal(body.u, 'admin');
  assert.ok(Math.abs(Date.now() - body.t) < 5000 && body.n.length >= 8);
  const reply = (fields: object) => {
    const nonce = nacl.randomBytes(24);
    const box = nacl.box(new TextEncoder().encode(JSON.stringify(fields)), nonce, raw.subarray(0, 32), server.secretKey);
    return b64(new Uint8Array([...nonce, ...box]));
  };
  const other = seal(b64(server.publicKey), {});
  assert.throws(() => other.open(reply({ token: 'x', n: body.n })), LoginError); // a reply for another request
  assert.deepEqual(open(reply({ token: 'x', n: body.n })), { token: 'x', n: body.n });
  assert.throws(() => open(reply({ token: 'x', n: body.n })), LoginError); // the key is wiped: a reply is read once
});

test('record types: RDATA parses into the form fields and composes back', () => {
  const cases: [string, string][] = [['A', '10.0.0.20'], ['MX', '10 mail.corp.lan.'], ['SRV', '0 5 5060 sip.corp.lan.'], ['CAA', '0 issue "letsencrypt.org"'],
    ['TXT', '"v=spf1 -all"']];
  for (const [type, value] of cases) {
    const fields = parse(SPEC[type], value);
    assert.ok(fields, `${type}: ${value}`);
    assert.deepEqual(tokenize(compose(SPEC[type], fields!)), tokenize(value), type);
  }
  assert.equal(parse(SPEC['MX'], 'mail.corp.lan.'), null); // the priority is missing: the raw editor is used
  assert.deepEqual(tokenize('"a \\"b\\" c" d'), [{ t: 'a "b" c', q: true }, { t: 'd', q: false }]);
  assert.equal(compose(SPEC['TXT'], { text: 'x'.repeat(300) }).split(' ').length, 2); // strings of 255 at most
  for (const spec of TYPE_SPECS) assert.equal(SPEC[spec.type], spec);
});

test('validate: numbers are plain digits', () => {
  const prio = SPEC['MX'].fields[0];
  assert.equal(validate(prio, '10'), '');
  for (const bad of ['1e3', '0x10', '1.0', '-1', '70000']) assert.notEqual(validate(prio, bad), '', bad);
});

test('errorText: only the strings of the error body', () => {
  assert.equal(errorText({ error: { name: ['Taken.'], ip: ['Bad.'] } }), 'Taken. Bad.');
  assert.equal(errorText({ error: { detail: 'Second factor required.', mfa_required: true } }), 'Second factor required.');
  assert.equal(errorText({ error: '<html>502</html>', message: 'Http failure response: 502' }), 'Http failure response: 502');
  assert.equal(errorText({ error: { isTrusted: true }, message: 'Http failure response: 0 Unknown Error' }), 'Http failure response: 0 Unknown Error'); // network error
  assert.equal(errorText({ message: 'Cancelled or timed out.' }), 'Cancelled or timed out.');
});
