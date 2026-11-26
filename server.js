const http = require('http');
const https = require('https');
const tls = require('tls');
const dns = require('dns').promises;
const url = require('url');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const PUBLIC = path.join(__dirname, 'public');

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => resolve(data));
  });
}

function serveStatic(req, res) {
  let filePath = req.url.split('?')[0];
  if (filePath === '/') filePath = '/index.html';
  const full = path.join(PUBLIC, filePath);
  if (!full.startsWith(PUBLIC)) { res.statusCode = 403; res.end('Forbidden'); return; }
  fs.readFile(full, (err, data) => {
    if (err) { res.statusCode = 404; res.end('Not found'); return; }
    const ext = path.extname(full).toLowerCase();
    const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.json': 'application/json', '.svg': 'image/svg+xml' };
    res.setHeader('Content-Type', types[ext] || 'application/octet-stream');
    res.end(data);
  });
}

function normalizeUrl(input) {
  let u = input.trim();
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  return u;
}

function fetchUrl(target, redirectCount = 0) {
  return new Promise((resolve) => {
    const parsed = new URL(target);
    const lib = parsed.protocol === 'https:' ? https : http;
    const opts = {
      method: 'GET',
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      headers: { 'User-Agent': 'NIS2-Compliance-Scanner/1.0', 'Accept': 'text/html,*/*' },
      timeout: 15000,
    };
    const req = lib.request(opts, (res) => {
      let body = '';
      res.on('data', (c) => { if (body.length < 200000) body += c; });
      res.on('end', () => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirectCount < 5) {
          const next = new URL(res.headers.location, target).toString();
          resolve({ redirect: next, status: res.statusCode, headers: res.headers, body: '', finalUrl: target });
          return;
        }
        resolve({ status: res.statusCode, headers: res.headers, body, finalUrl: target, redirect: null });
      });
    });
    req.on('error', (e) => resolve({ error: e.message, status: 0, headers: {}, body: '', finalUrl: target }));
    req.on('timeout', () => { req.destroy(); resolve({ error: 'timeout', status: 0, headers: {}, body: '', finalUrl: target }); });
    req.end();
  });
}

function tlsInfo(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate(true);
      const info = {
        authorized: socket.authorized,
        authorizationError: socket.authorizationError,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher(),
        cert: cert ? {
          subject: cert.subject,
          issuer: cert.issuer,
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          fingerprint256: cert.fingerprint256,
          serialNumber: cert.serialNumber,
          altNames: cert.subjectaltname,
        } : null,
      };
      socket.end();
      resolve(info);
    });
    socket.on('error', (e) => resolve({ error: e.message }));
    socket.setTimeout(10000, () => { socket.destroy(); resolve({ error: 'timeout' }); });
  });
}

async function dnsChecks(hostname) {
  const result = { a: [], mx: [], txt: [], spf: null, dmarc: null, dnssec: null };
  try { result.a = await dns.resolve4(hostname); } catch (e) { result.aError = e.code; }
  try { result.mx = await dns.resolveMx(hostname); } catch (e) { result.mxError = e.code; }
  try {
    const txt = await dns.resolveTxt(hostname);
    result.txt = txt.map((t) => t.join(''));
    result.spf = result.txt.find((t) => /^v=spf1/i.test(t)) || null;
  } catch (e) { result.txtError = e.code; }
  try {
    const dmarcTxt = await dns.resolveTxt('_dmarc.' + hostname);
    const flat = dmarcTxt.map((t) => t.join(''));
    result.dmarc = flat.find((t) => /^v=DMARC1/i.test(t)) || flat[0] || null;
  } catch (e) { result.dmarcError = e.code; }
  return result;
}

const IMPROVEMENTS = {
  https: {
    reference: { title: 'Mozilla Web Security Guidelines — Transport Layer', url: 'https://infosec.mozilla.org/guidelines/web_security#transport-layer' },
    suggestion: 'Brug HTTPS på alle sider. Skaf et gratis certifikat (fx Let’s Encrypt) og omdirigér HTTP til HTTPS.',
  },
  tls: {
    reference: { title: 'Mozilla TLS Configuration Guidelines', url: 'https://wiki.mozilla.org/Security/Server_Side_TLS' },
    suggestion: 'Brug TLS 1.2+ (helst 1.3), et gyldigt certifikat fra en betroet CA og forny inden udløb. Deaktiver svage ciphers.',
  },
  'http-redirect': {
    reference: { title: 'Mozilla Web Security Guidelines — Transport Layer', url: 'https://infosec.mozilla.org/guidelines/web_security#transport-layer' },
    suggestion: 'Konfigurér webserveren til at svare 301/308 fra http:// til https:// for alle stier.',
  },
  reachable: {
    reference: { title: 'NIS2-direktivet (EU) 2022/2555', url: 'https://eur-lex.europa.eu/eli/dir/2022/2555/oj' },
    suggestion: 'Sørg for at siden er tilgængelig og returnerer 2xx/3xx. Overvåg uptime og fejl.',
  },
  hsts: {
    reference: { title: 'OWASP HTTP Strict Transport Security Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html' },
    suggestion: 'Tilføj header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.',
  },
  csp: {
    reference: { title: 'OWASP Content Security Policy Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html' },
    suggestion: 'Tilføj en CSP, fx `Content-Security-Policy: default-src \'self\'; object-src \'none\'; base-uri \'self\'`.',
  },
  xfo: {
    reference: { title: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' },
    suggestion: 'Tilføj `X-Frame-Options: DENY` (eller `SAMEORIGIN`) for at forhindre clickjacking.',
  },
  xcto: {
    reference: { title: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' },
    suggestion: 'Tilføj `X-Content-Type-Options: nosniff`.',
  },
  referrer: {
    reference: { title: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' },
    suggestion: 'Tilføj `Referrer-Policy: strict-origin-when-cross-origin` (eller `no-referrer`).',
  },
  permissions: {
    reference: { title: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' },
    suggestion: 'Tilføj `Permissions-Policy` der deaktiverer ubrugte features, fx `camera=(), microphone=(), geolocation=()`.',
  },
  'server-disclosure': {
    reference: { title: 'OWASP — Information Leakage', url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server' },
    suggestion: 'Skjul `Server` og `X-Powered-By`-headers i webserver/konfiguration.',
  },
  cookies: {
    reference: { title: 'OWASP Session Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html' },
    suggestion: 'Sæt `Secure; HttpOnly; SameSite=Lax` (eller Strict) på alle cookies.',
  },
  spf: {
    reference: { title: 'RFC 7208 — Sender Policy Framework', url: 'https://www.rfc-editor.org/rfc/rfc7208' },
    suggestion: 'Opret en TXT-record på domænet: `v=spf1 ... -all` (begræns afsendere).',
  },
  dmarc: {
    reference: { title: 'RFC 7489 — DMARC', url: 'https://www.rfc-editor.org/rfc/rfc7489' },
    suggestion: 'Opret `_dmarc.<domæne>` TXT: `v=DMARC1; p=quarantine; rua=mailto:...`.',
  },
  'security-txt': {
    reference: { title: 'RFC 9116 — security.txt', url: 'https://www.rfc-editor.org/rfc/rfc9116' },
    suggestion: 'Opret `/.well-known/security.txt` med kontaktinfo for sårbarhedsrapportering.',
  },
  'tls-version': {
    reference: { title: 'Mozilla TLS Configuration Guidelines', url: 'https://wiki.mozilla.org/Security/Server_Side_TLS' },
    suggestion: 'Deaktiver TLS 1.0/1.1; brug kun TLS 1.2+ (helst 1.3).',
  },
  'hsts-preload': {
    reference: { title: 'HSTS Preload List', url: 'https://hstspreload.org/' },
    suggestion: 'Tilføj `preload` og `includeSubDomains` til HSTS-headeren og indsend domænet til preload-listen.',
  },
  'mixed-content': {
    reference: { title: 'MDN — Mixed Content', url: 'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content' },
    suggestion: 'Erstat alle `http://`-ressourcer med `https://` (eller protokol-relative URLer).',
  },
  coop: {
    reference: { title: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' },
    suggestion: 'Tilføj `Cross-Origin-Opener-Policy: same-origin`.',
  },
  coep: {
    reference: { title: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' },
    suggestion: 'Tilføj `Cross-Origin-Embedder-Policy: require-corp`.',
  },
  corp: {
    reference: { title: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' },
    suggestion: 'Tilføj `Cross-Origin-Resource-Policy: same-origin`.',
  },
  'csp-report': {
    reference: { title: 'OWASP Content Security Policy Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html' },
    suggestion: 'Tilføj `report-uri`/`report-to` til CSP for at modtage overtrædelsesrapporter.',
  },
  dnssec: {
    reference: { title: 'DNSSEC — ICANN', url: 'https://www.icann.org/resources/pages/dnssec-what-is-it-2019-03-06-en' },
    suggestion: 'Aktivér DNSSEC hos din DNS-udbyder og publicér DS-record hos registrar.',
  },
  'dmarc-policy': {
    reference: { title: 'RFC 7489 — DMARC', url: 'https://www.rfc-editor.org/rfc/rfc7489' },
    suggestion: 'Sæt DMARC-politik til `p=quarantine` eller `p=reject`.',
  },
  'spf-strict': {
    reference: { title: 'RFC 7208 — SPF', url: 'https://www.rfc-editor.org/rfc/rfc7208' },
    suggestion: 'Afslut SPF med `-all` (hardfail) i stedet for `~all`.',
  },
  'directory-listing': {
    reference: { title: 'OWASP — Forced Browsing', url: 'https://owasp.org/www-community/attacks/Forced_browsing' },
    suggestion: 'Deaktiver directory listing i webserver (fx `Options -Indexes` i Apache).',
  },
  'error-pages': {
    reference: { title: 'OWASP — Error Handling', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html' },
    suggestion: 'Brug egne fejlsider uden stack traces og server-version.',
  },
  sri: {
    reference: { title: 'MDN — Subresource Integrity', url: 'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity' },
    suggestion: 'Tilføj `integrity="sha384-..."` og `crossorigin="anonymous"` til eksterne scripts/styles.',
  },
  'cookie-prefix': {
    reference: { title: 'MDN — Cookie prefixes', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes' },
    suggestion: 'Brug `__Host-` eller `__Secure-` præfiks på sikkerhedsrelevante cookies.',
  },
  caa: {
    reference: { title: 'RFC 8659 — CAA', url: 'https://www.rfc-editor.org/rfc/rfc8659' },
    suggestion: 'Opret en CAA DNS-record der begrænser hvilke CA’er må udstede certifikater for domænet.',
  },
  'hsts-maxage': {
    reference: { title: 'OWASP HSTS Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html' },
    suggestion: 'Sæt HSTS `max-age` til mindst 31536000 (1 år).',
  },
  'csp-unsafe': {
    reference: { title: 'OWASP CSP Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html' },
    suggestion: 'Fjern `unsafe-inline` og `unsafe-eval` fra CSP; brug nonces/hashes i stedet.',
  },
  'csp-frame-ancestors': {
    reference: { title: 'OWASP CSP Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html' },
    suggestion: 'Tilføj `frame-ancestors \'none\'` (eller `self`) til CSP.',
  },
  'cors-wildcard': {
    reference: { title: 'OWASP CORS', url: 'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny' },
    suggestion: 'Undgå `Access-Control-Allow-Origin: *` på endpoints med credentials; angiv eksplicitte origins.',
  },
  'cache-control': {
    reference: { title: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' },
    suggestion: 'Sæt `Cache-Control: no-store` på sider med session/brugerdata.',
  },
  'mta-sts': {
    reference: { title: 'RFC 8461 — MTA-STS', url: 'https://www.rfc-editor.org/rfc/rfc8461' },
    suggestion: 'Publicér `_mta-sts.<domæne>` TXT og en MTA-STS-policy for sikker mailtransport.',
  },
  tlsrpt: {
    reference: { title: 'RFC 8460 — TLSRPT', url: 'https://www.rfc-editor.org/rfc/rfc8460' },
    suggestion: 'Publicér `_smtp._tls.<domæne>` TXT med `v=TLSRPTv1; rua=mailto:...`.',
  },
};

async function scan(targetUrl) {
  const normalized = normalizeUrl(targetUrl);
  const parsed = new URL(normalized);
  const hostname = parsed.hostname;
  const isHttps = parsed.protocol === 'https:';

  const checks = [];

  // 1. HTTPS
  checks.push({
    id: 'https',
    title: 'HTTPS / TLS kryptering',
    category: 'Kryptering',
    pass: isHttps,
    detail: isHttps ? 'Siden bruger HTTPS.' : 'Siden bruger ikke HTTPS — data sendes ukrypteret.',
    weight: 20,
  });

  // 2. TLS cert
  let tlsData = null;
  if (isHttps) {
    tlsData = await tlsInfo(hostname);
    if (tlsData.error) {
      checks.push({ id: 'tls', title: 'TLS-certifikat', category: 'Kryptering', pass: false, detail: 'Kunne ikke hente certifikat: ' + tlsData.error, weight: 15 });
    } else {
      const cert = tlsData.cert;
      const validTo = cert ? new Date(cert.valid_to) : null;
      const daysLeft = validTo ? Math.floor((validTo - Date.now()) / 86400000) : null;
      const certOk = tlsData.authorized && daysLeft !== null && daysLeft > 0;
      checks.push({
        id: 'tls',
        title: 'TLS-certifikat (gyldigt & ikke udløbet)',
        category: 'Kryptering',
        pass: certOk,
        detail: tlsData.authorized
          ? `Certifikat gyldigt. Udløber om ${daysLeft} dage (${cert.valid_to}). Protokol: ${tlsData.protocol}.`
          : `Certifikatproblem: ${tlsData.authorizationError || 'ukendt'}.`,
        weight: 15,
        extra: { protocol: tlsData.protocol, cipher: tlsData.cipher && tlsData.cipher.name, valid_to: cert && cert.valid_to, days_left: daysLeft },
      });
    }
  }

  // 3. HTTP -> HTTPS redirect
  let httpRedirect = false;
  if (isHttps) {
    try {
      const httpRes = await fetchUrl('http://' + hostname + (parsed.pathname || '/'));
      httpRedirect = httpRes.status >= 300 && httpRes.status < 400 && httpRes.headers.location && String(httpRes.headers.location).startsWith('https');
    } catch (e) {}
  }
  checks.push({
    id: 'http-redirect',
    title: 'HTTP → HTTPS omdirigering',
    category: 'Kryptering',
    pass: httpRedirect,
    detail: httpRedirect ? 'HTTP omdirigerer til HTTPS.' : 'Ingen automatisk omdirigering fra HTTP til HTTPS fundet.',
    weight: 10,
  });

  // 4. Fetch page
  const page = await fetchUrl(normalized);
  if (page.error) {
    checks.push({ id: 'reachable', title: 'Siden er tilgængelig', category: 'Tilgængelighed', pass: false, detail: 'Fejl: ' + page.error, weight: 10 });
  } else {
    checks.push({ id: 'reachable', title: 'Siden er tilgængelig', category: 'Tilgængelighed', pass: page.status >= 200 && page.status < 400, detail: `HTTP ${page.status}`, weight: 10 });
  }

  const headers = page.headers || {};
  const h = (k) => headers[k.toLowerCase()];

  // 5. HSTS
  const hsts = h('strict-transport-security');
  checks.push({
    id: 'hsts',
    title: 'HSTS (Strict-Transport-Security)',
    category: 'Sikkerhedsheaders',
    pass: !!hsts,
    detail: hsts ? `HSTS sat: ${hsts}` : 'HSTS-header mangler.',
    weight: 10,
  });

  // 6. CSP
  const csp = h('content-security-policy');
  checks.push({
    id: 'csp',
    title: 'Content-Security-Policy',
    category: 'Sikkerhedsheaders',
    pass: !!csp,
    detail: csp ? 'CSP sat.' : 'CSP-header mangler.',
    weight: 10,
  });

  // 7. X-Frame-Options
  const xfo = h('x-frame-options');
  checks.push({
    id: 'xfo',
    title: 'X-Frame-Options (clickjacking-beskyttelse)',
    category: 'Sikkerhedsheaders',
    pass: !!xfo,
    detail: xfo ? `X-Frame-Options: ${xfo}` : 'X-Frame-Options mangler.',
    weight: 8,
  });

  // 8. X-Content-Type-Options
  const xcto = h('x-content-type-options');
  checks.push({
    id: 'xcto',
    title: 'X-Content-Type-Options: nosniff',
    category: 'Sikkerhedsheaders',
    pass: String(xcto).toLowerCase() === 'nosniff',
    detail: xcto ? `X-Content-Type-Options: ${xcto}` : 'X-Content-Type-Options mangler.',
    weight: 8,
  });

  // 9. Referrer-Policy
  const rp = h('referrer-policy');
  checks.push({
    id: 'referrer',
    title: 'Referrer-Policy',
    category: 'Sikkerhedsheaders',
    pass: !!rp,
    detail: rp ? `Referrer-Policy: ${rp}` : 'Referrer-Policy mangler.',
    weight: 6,
  });

  // 10. Permissions-Policy
  const pp = h('permissions-policy') || h('feature-policy');
  checks.push({
    id: 'permissions',
    title: 'Permissions-Policy',
    category: 'Sikkerhedsheaders',
    pass: !!pp,
    detail: pp ? 'Permissions-Policy sat.' : 'Permissions-Policy mangler.',
    weight: 6,
  });

  // 11. Server disclosure
  const server = h('server');
  const powered = h('x-powered-by');
  const disclosed = !!(server || powered);
  // pass = NOT disclosed (we want no disclosure)
  checks.push({
    id: 'server-disclosure',
    title: 'Server-information skjult (ingen Server/X-Powered-By)',
    category: 'Informationsskjulning',
    pass: !disclosed,
    detail: disclosed ? `Afsløret: Server="${server || '-'}", X-Powered-By="${powered || '-'}"` : 'Ingen server-teknologi afsløret.',
    weight: 8,
  });

  // 12. Cookies
  const setCookie = headers['set-cookie'];
  const cookies = Array.isArray(setCookie) ? setCookie : (setCookie ? [setCookie] : []);
  let cookieIssues = [];
  let cookiePass = true;
  if (cookies.length === 0) {
    checks.push({ id: 'cookies', title: 'Cookie-sikkerhed (Secure/HttpOnly/SameSite)', category: 'Cookies', pass: true, detail: 'Ingen cookies sat på forsiden.', weight: 8 });
  } else {
    cookies.forEach((c) => {
      const low = c.toLowerCase();
      if (!low.includes('secure')) cookieIssues.push('mangler Secure');
      if (!low.includes('httponly')) cookieIssues.push('mangler HttpOnly');
      if (!low.includes('samesite')) cookieIssues.push('mangler SameSite');
    });
    cookiePass = cookieIssues.length === 0;
    checks.push({
      id: 'cookies',
      title: 'Cookie-sikkerhed (Secure/HttpOnly/SameSite)',
      category: 'Cookies',
      pass: cookiePass,
      detail: cookiePass ? `${cookies.length} cookie(s) — alle har Secure/HttpOnly/SameSite.` : `${cookies.length} cookie(s) med problemer: ${[...new Set(cookieIssues)].join(', ')}.`,
      weight: 8,
    });
  }

  // 13. DNS checks
  const dnsr = await dnsChecks(hostname);
  checks.push({
    id: 'spf',
    title: 'SPF-record (email-forfalskning)',
    category: 'DNS-sikkerhed',
    pass: !!dnsr.spf,
    detail: dnsr.spf ? `SPF fundet: ${dnsr.spf}` : 'Ingen SPF-record fundet.',
    weight: 6,
  });
  checks.push({
    id: 'dmarc',
    title: 'DMARC-record',
    category: 'DNS-sikkerhed',
    pass: !!dnsr.dmarc,
    detail: dnsr.dmarc ? `DMARC fundet: ${dnsr.dmarc}` : 'Ingen DMARC-record fundet.',
    weight: 6,
  });

  // 14. security.txt
  let securityTxt = false;
  try {
    const st = await fetchUrl(normalized.replace(/\/$/, '') + '/.well-known/security.txt');
    securityTxt = st.status === 200;
  } catch (e) {}
  checks.push({
    id: 'security-txt',
    title: 'security.txt (kontakt for sårbarhedsrapportering)',
    category: 'Transparens',
    pass: securityTxt,
    detail: securityTxt ? 'security.txt fundet.' : 'Ingen security.txt fundet.',
    weight: 4,
  });

  // TLS version
  if (isHttps && tlsData && !tlsData.error) {
    const proto = tlsData.protocol || '';
    const ok = /TLSv1\.[23]/.test(proto) || proto === 'TLSv1.3';
    checks.push({ id: 'tls-version', title: 'Moderne TLS-version (1.2+)', category: 'Kryptering', pass: ok, detail: `Protokol: ${proto}.`, weight: 8 });
  }

  // HSTS preload
  checks.push({
    id: 'hsts-preload',
    title: 'HSTS med preload + includeSubDomains',
    category: 'Sikkerhedsheaders',
    pass: !!hsts && /includeSubDomains/i.test(hsts) && /preload/i.test(hsts),
    detail: hsts ? `HSTS: ${hsts}` : 'HSTS mangler.',
    weight: 6,
  });

  // Mixed content
  let mixed = false;
  if (page.body) mixed = /<(script|link|img)[^>]+src=["']http:/i.test(page.body) || /<link[^>]+href=["']http:/i.test(page.body);
  checks.push({ id: 'mixed-content', title: 'Ingen mixed content (http:// på https-side)', category: 'Kryptering', pass: !mixed, detail: mixed ? 'Mixed content fundet i HTML.' : 'Ingen mixed content fundet.', weight: 8 });

  // COOP / COEP / CORP
  const coop = h('cross-origin-opener-policy');
  const coep = h('cross-origin-embedder-policy');
  const corp = h('cross-origin-resource-policy');
  checks.push({ id: 'coop', title: 'Cross-Origin-Opener-Policy', category: 'Sikkerhedsheaders', pass: !!coop, detail: coop ? `COOP: ${coop}` : 'COOP mangler.', weight: 5 });
  checks.push({ id: 'coep', title: 'Cross-Origin-Embedder-Policy', category: 'Sikkerhedsheaders', pass: !!coep, detail: coep ? `COEP: ${coep}` : 'COEP mangler.', weight: 5 });
  checks.push({ id: 'corp', title: 'Cross-Origin-Resource-Policy', category: 'Sikkerhedsheaders', pass: !!corp, detail: corp ? `CORP: ${corp}` : 'CORP mangler.', weight: 5 });

  // CSP report
  checks.push({
    id: 'csp-report',
    title: 'CSP med report-uri/report-to',
    category: 'Sikkerhedsheaders',
    pass: !!csp && /report-(uri|to)/i.test(csp),
    detail: csp ? 'CSP sat.' : 'CSP mangler.',
    weight: 4,
  });

  // DNSSEC (best-effort)
  let dnssecOk = false;
  try {
    const r = await dns.resolve(hostname, 'DNSKEY');
    dnssecOk = Array.isArray(r) && r.length > 0;
  } catch (e) { dnssecOk = false; }
  checks.push({ id: 'dnssec', title: 'DNSSEC aktiveret', category: 'DNS-sikkerhed', pass: dnssecOk, detail: dnssecOk ? 'DNSKEY fundet.' : 'Ingen DNSKEY fundet (eller resolver understøtter ikke DNSSEC).', weight: 6 });

  // DMARC policy strict
  const dmarcPolicy = dnsr.dmarc ? (/p\s*=\s*(reject|quarantine)/i.test(dnsr.dmarc)) : false;
  checks.push({ id: 'dmarc-policy', title: 'DMARC-politik (quarantine/reject)', category: 'DNS-sikkerhed', pass: dmarcPolicy, detail: dnsr.dmarc ? dnsr.dmarc : 'Ingen DMARC.', weight: 5 });

  // SPF strict
  const spfStrict = dnsr.spf ? /-all\s*$/.test(dnsr.spf.trim()) : false;
  checks.push({ id: 'spf-strict', title: 'SPF hardfail (-all)', category: 'DNS-sikkerhed', pass: spfStrict, detail: dnsr.spf ? dnsr.spf : 'Ingen SPF.', weight: 4 });

  // Directory listing
  let dirListing = false;
  try {
    const r = await fetchUrl(normalized.replace(/\/$/, '') + '/');
    if (r.body && /Index of \//i.test(r.body)) dirListing = true;
  } catch (e) {}
  checks.push({ id: 'directory-listing', title: 'Ingen directory listing', category: 'Konfiguration', pass: !dirListing, detail: dirListing ? 'Directory listing ser ud til at være aktiv.' : 'Ingen directory listing fundet.', weight: 4 });

  // Error pages
  let errorLeak = false;
  try {
    const r = await fetchUrl(normalized.replace(/\/$/, '') + '/this-page-does-not-exist-xyz123');
    if (r.body && /(stack trace|at .*:\d+:\d+|X-Powered-By)/i.test(r.body)) errorLeak = true;
  } catch (e) {}
  checks.push({ id: 'error-pages', title: 'Fejlsider uden stack trace', category: 'Konfiguration', pass: !errorLeak, detail: errorLeak ? ' mulig information leakage i fejlsvar.' : 'Ingen synlig stack trace i 404-svar.', weight: 4 });

  // SRI
  let sriMissing = false;
  if (page.body) {
    const scripts = page.body.match(/<script[^>]+src=["']https?:\/\/[^"']+["'][^>]*>/gi) || [];
    sriMissing = scripts.some((s) => !/integrity=/i.test(s));
  }
  checks.push({ id: 'sri', title: 'Subresource Integrity på eksterne scripts', category: 'Integritet', pass: !sriMissing && (page.body ? /<script[^>]+src=["']https?:\/\//i.test(page.body) === false || true : true), detail: sriMissing ? 'Eksterne scripts uden integrity fundet.' : 'Ingen eksterne scripts uden SRI (eller ingen eksterne scripts).', weight: 5 });

  // Cookie prefix
  let prefixOk = true;
  if (cookies.length > 0) {
    prefixOk = cookies.every((c) => /^(__Host-|__Secure-)/i.test(c.split('=')[0].trim()));
  }
  checks.push({ id: 'cookie-prefix', title: 'Cookie-præfikser (__Host-/__Secure-)', category: 'Cookies', pass: cookies.length === 0 ? true : prefixOk, detail: cookies.length === 0 ? 'Ingen cookies.' : (prefixOk ? 'Alle cookies bruger sikre præfikser.' : 'Nogle cookies mangler sikre præfikser.'), weight: 4 });

  // CAA
  let caaOk = false;
  try {
    const r = await dns.resolve(hostname, 'CAA');
    caaOk = Array.isArray(r) && r.length > 0;
  } catch (e) { caaOk = false; }
  checks.push({ id: 'caa', title: 'DNS CAA-record', category: 'DNS-sikkerhed', pass: caaOk, detail: caaOk ? 'CAA fundet.' : 'Ingen CAA-record fundet.', weight: 4 });

  // HSTS max-age
  let hstsMaxAgeOk = false;
  if (hsts) {
    const m = hsts.match(/max-age=(\d+)/i);
    hstsMaxAgeOk = !!m && parseInt(m[1]) >= 31536000;
  }
  checks.push({ id: 'hsts-maxage', title: 'HSTS max-age ≥ 1 år', category: 'Sikkerhedsheaders', pass: hstsMaxAgeOk, detail: hsts ? `HSTS: ${hsts}` : 'HSTS mangler.', weight: 4 });

  // CSP unsafe
  const cspUnsafe = !!csp && /unsafe-(inline|eval)/i.test(csp);
  checks.push({ id: 'csp-unsafe', title: 'CSP uden unsafe-inline/eval', category: 'Sikkerhedsheaders', pass: !!csp && !cspUnsafe, detail: csp ? (cspUnsafe ? 'CSP indeholder unsafe-inline/eval.' : 'CSP ser sikker ud.') : 'CSP mangler.', weight: 5 });

  // CSP frame-ancestors
  const cspFA = !!csp && /frame-ancestors/i.test(csp);
  checks.push({ id: 'csp-frame-ancestors', title: 'CSP frame-ancestors sat', category: 'Sikkerhedsheaders', pass: cspFA, detail: cspFA ? 'frame-ancestors sat.' : 'frame-ancestors mangler.', weight: 4 });

  // CORS wildcard
  const acao = h('access-control-allow-origin');
  const corsWildcard = acao === '*';
  checks.push({ id: 'cors-wildcard', title: 'CORS ikke wildcard (*)', category: 'Sikkerhedsheaders', pass: !corsWildcard, detail: acao ? `ACAO: ${acao}` : 'Ingen CORS-header.', weight: 4 });

  // Cache-Control
  const cc = h('cache-control') || '';
  const cacheOk = /no-store/i.test(cc);
  checks.push({ id: 'cache-control', title: 'Cache-Control: no-store', category: 'Sikkerhedsheaders', pass: cacheOk, detail: cc ? `Cache-Control: ${cc}` : 'Cache-Control mangler.', weight: 4 });

  // MTA-STS
  let mtaSts = false;
  try {
    const r = await dns.resolveTxt('_mta-sts.' + hostname);
    mtaSts = Array.isArray(r) && r.length > 0;
  } catch (e) { mtaSts = false; }
  checks.push({ id: 'mta-sts', title: 'MTA-STS (mail)', category: 'DNS-sikkerhed', pass: mtaSts, detail: mtaSts ? 'MTA-STS fundet.' : 'Ingen MTA-STS.', weight: 3 });

  // TLSRPT
  let tlsrpt = false;
  try {
    const r = await dns.resolveTxt('_smtp._tls.' + hostname);
    tlsrpt = Array.isArray(r) && r.length > 0;
  } catch (e) { tlsrpt = false; }
  checks.push({ id: 'tlsrpt', title: 'TLS-RPT (mail)', category: 'DNS-sikkerhed', pass: tlsrpt, detail: tlsrpt ? 'TLS-RPT fundet.' : 'Ingen TLS-RPT.', weight: 3 });

  // Score
  const totalWeight = checks.reduce((s, c) => s + c.weight, 0);
  const earned = checks.reduce((s, c) => s + (c.pass ? c.weight : 0), 0);
  const score = Math.round((earned / totalWeight) * 100);

  let grade = 'F';
  if (score >= 90) grade = 'A';
  else if (score >= 75) grade = 'B';
  else if (score >= 60) grade = 'C';
  else if (score >= 45) grade = 'D';
  else if (score >= 30) grade = 'E';

  const enrichedChecks = checks.map((c) => {
    const imp = IMPROVEMENTS[c.id] || {};
    return { ...c, reference: imp.reference || null, suggestion: imp.suggestion || '' };
  });

  return {
    url: normalized,
    hostname,
    score,
    grade,
    totalWeight,
    earned,
    checks: enrichedChecks,
    dns: dnsr,
    tls: tlsData,
    headers,
    scannedAt: new Date().toISOString(),
  };
}

const rateLimit = new Map();
function checkRate(ip) {
  const now = Date.now();
  const window = 60000;
  const max = 10;
  const arr = (rateLimit.get(ip) || []).filter((t) => now - t < window);
  if (arr.length >= max) return false;
  arr.push(now);
  rateLimit.set(ip, arr);
  return true;
}

function isPrivateHost(hostname) {
  // block obvious local/private names
  if (hostname === 'localhost' || hostname.endsWith('.local') || hostname.endsWith('.internal')) return true;
  // IPv4
  const m = hostname.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const [a,b] = [parseInt(m[1]), parseInt(m[2])];
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }
  return false;
}

const server = http.createServer(async (req, res) => {
  const ip = req.socket.remoteAddress || 'unknown';
  if (req.method === 'POST' && req.url === '/api/scan') {
    if (!checkRate(ip)) { res.statusCode = 429; res.setHeader('Content-Type','application/json'); res.end(JSON.stringify({error:'Too many requests'})); return; }
    const body = await readBody(req);
    let payload = {};
    try { payload = JSON.parse(body); } catch (e) {}
    if (!payload.url) { res.statusCode = 400; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ error: 'url required' })); return; }
    let normalized;
    try { normalized = normalizeUrl(payload.url); } catch (e) { res.statusCode = 400; res.setHeader('Content-Type','application/json'); res.end(JSON.stringify({error:'invalid url'})); return; }
    let parsed;
    try { parsed = new URL(normalized); } catch (e) { res.statusCode = 400; res.setHeader('Content-Type','application/json'); res.end(JSON.stringify({error:'invalid url'})); return; }
    if (!['http:','https:'].includes(parsed.protocol)) { res.statusCode = 400; res.setHeader('Content-Type','application/json'); res.end(JSON.stringify({error:'only http/https allowed'})); return; }
    if (isPrivateHost(parsed.hostname)) { res.statusCode = 400; res.setHeader('Content-Type','application/json'); res.end(JSON.stringify({error:'private/local hosts are not allowed'})); return; }
    try {
      const result = await scan(payload.url);
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(result));
    } catch (e) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }
  serveStatic(req, res);
});

server.listen(PORT, () => {
  console.log(`NIS2 scanner running on http://localhost:${PORT}`);
});
