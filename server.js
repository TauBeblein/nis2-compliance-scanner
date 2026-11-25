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

const server = http.createServer(async (req, res) => {
  if (req.method === 'POST' && req.url === '/api/scan') {
    const body = await readBody(req);
    let payload = {};
    try { payload = JSON.parse(body); } catch (e) {}
    if (!payload.url) { res.statusCode = 400; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ error: 'url required' })); return; }
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
