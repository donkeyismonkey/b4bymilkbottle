'use strict';

const http = require('http');
const https = require('https');
const crypto = require('crypto');

function required(name) {
  const value = process.env[name];

  if (!value) {
    throw new Error('Missing environment variable ' + name);
  }

  return value;
}

function list(name) {
  return (process.env[name] || '').split(',').map((entry) => entry.trim()).filter(Boolean);
}

const config = {
  port: Number(process.env.PORT || 8080),
  b4byAppId: required('B4BY_APP_ID'),
  metaAppId: required('META_APP_ID'),
  metaAppSecret: required('META_APP_SECRET'),
  signingKey: required('B4BY_SIGNING_KEY'),
  allowedPackages: list('B4BY_ALLOWED_PACKAGES'),
  allowedCerts: list('B4BY_ALLOWED_CERTS').map((entry) => entry.toLowerCase()),
  minDeviceIntegrity: process.env.B4BY_MIN_DEVICE_INTEGRITY || 'Basic',
  requireEntitlement: process.env.B4BY_REQUIRE_ENTITLEMENT !== '0',
  requireStoreRecognized: process.env.B4BY_REQUIRE_STORE_RECOGNIZED === '1',
  maxTokenAgeSeconds: 600,
  trustProxy: process.env.B4BY_TRUST_PROXY === '1',
  nonceTtlMs: 120000,
  receiptTtlSeconds: 3600,
  requestsPerMinute: 60,
  maxBodyBytes: 16384
};

const INTEGRITY_RANK = { NotTrusted: 0, Basic: 1, Advanced: 2 };
const nonces = new Map();
const hits = new Map();

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function accessToken() {
  return 'OC|' + config.metaAppId + '|' + config.metaAppSecret;
}

function send(response, status, body) {
  const text = JSON.stringify(body);
  response.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) });
  response.end(text);
}

function clientAddress(request) {
  if (config.trustProxy && request.headers['x-forwarded-for']) {
    return String(request.headers['x-forwarded-for']).split(',')[0].trim();
  }

  return request.socket.remoteAddress || 'unknown';
}

function rateLimited(address) {
  const now = Date.now();
  const entry = hits.get(address);

  if (!entry || now > entry.resetAt) {
    hits.set(address, { count: 1, resetAt: now + 60000 });
    return false;
  }

  entry.count += 1;
  return entry.count > config.requestsPerMinute;
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;

    request.on('data', (chunk) => {
      size += chunk.length;

      if (size > config.maxBodyBytes) {
        reject(new Error('too_large'));
        request.destroy();
        return;
      }

      chunks.push(chunk);
    });

    request.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch (error) {
        reject(new Error('bad_json'));
      }
    });

    request.on('error', reject);
  });
}

function metaRequest(method, path, params) {
  return new Promise((resolve, reject) => {
    const query = new URLSearchParams(params).toString();
    const options = {
      hostname: 'graph.oculus.com',
      path: method === 'GET' ? path + '?' + query : path,
      method,
      timeout: 8000,
      headers: {}
    };

    let body = null;

    if (method === 'POST') {
      body = query;
      options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      options.headers['Content-Length'] = Buffer.byteLength(body);
    }

    const request = https.request(options, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch (error) {
          reject(error);
        }
      });
    });

    request.on('timeout', () => request.destroy(new Error('timeout')));
    request.on('error', reject);

    if (body) {
      request.write(body);
    }

    request.end();
  });
}

function makeReceipt(userId, uniqueId) {
  const payload = Buffer.from(JSON.stringify({
    a: config.b4byAppId,
    u: userId || '',
    d: uniqueId ? crypto.createHash('sha256').update(String(uniqueId)).digest('hex').slice(0, 16) : '',
    exp: Math.floor(Date.now() / 1000) + config.receiptTtlSeconds
  })).toString('base64url');

  const signature = crypto.createHmac('sha256', config.signingKey).update(payload).digest('base64url');
  return payload + '.' + signature;
}

function verifyReceipt(receipt) {
  const parts = String(receipt || '').split('.');

  if (parts.length !== 2) {
    return null;
  }

  const expected = crypto.createHmac('sha256', config.signingKey).update(parts[0]).digest('base64url');

  if (!safeEqual(expected, parts[1])) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    return payload.exp > Math.floor(Date.now() / 1000) ? payload : null;
  } catch (error) {
    return null;
  }
}

function handleNonce(response) {
  const nonce = crypto.randomBytes(24).toString('base64url');
  nonces.set(nonce, Date.now() + config.nonceTtlMs);
  send(response, 200, { nonce });
}

async function handleVerify(request, response) {
  let body;

  try {
    body = await readJson(request);
  } catch (error) {
    send(response, 400, { ok: false, reason: error.message });
    return;
  }

  const nonce = String(body.nonce || '');
  const token = String(body.token || '');
  const userId = String(body.userId || '');
  const userProof = String(body.userProof || '');
  const expires = nonces.get(nonce);

  nonces.delete(nonce);

  if (!nonce || !token || !expires || expires < Date.now()) {
    send(response, 200, { ok: false, reason: 'bad_nonce' });
    return;
  }

  let verification;

  try {
    verification = await metaRequest('GET', '/platform_integrity/verify', { token, access_token: accessToken() });
  } catch (error) {
    send(response, 200, { ok: false, reason: 'meta_unreachable' });
    return;
  }

  const entry = verification && verification.data && verification.data[0];

  if (!entry || entry.message !== 'success' || !entry.claims) {
    send(response, 200, { ok: false, reason: 'attestation_invalid' });
    return;
  }

  let claims;

  try {
    claims = JSON.parse(Buffer.from(entry.claims, 'base64url').toString('utf8'));
  } catch (error) {
    send(response, 200, { ok: false, reason: 'attestation_unreadable' });
    return;
  }

  const details = claims.request_details || {};
  const app = claims.app_state || {};
  const device = claims.device_state || {};

  if (!details.nonce || !safeEqual(details.nonce, nonce)) {
    send(response, 200, { ok: false, reason: 'nonce_mismatch' });
    return;
  }

  const nowSeconds = Math.floor(Date.now() / 1000);

  if (!details.exp || details.exp < nowSeconds || !details.timestamp || nowSeconds - details.timestamp > config.maxTokenAgeSeconds) {
    send(response, 200, { ok: false, reason: 'token_stale' });
    return;
  }

  if (config.allowedPackages.length > 0 && config.allowedPackages.indexOf(app.package_id) === -1) {
    send(response, 200, { ok: false, reason: 'package_mismatch' });
    return;
  }

  if (config.requireStoreRecognized && app.app_integrity_state !== 'StoreRecognized') {
    send(response, 200, { ok: false, reason: 'not_store_recognized' });
    return;
  }

  const certs = Array.isArray(app.package_cert_sha256_digest) ? app.package_cert_sha256_digest.map((entry) => String(entry).toLowerCase()) : [];

  if (config.allowedCerts.length === 0) {
    console.log('[b4by] No B4BY_ALLOWED_CERTS set. Attested signing certificate digest(s): ' + certs.join(', '));
  } else if (certs.length === 0 || !certs.every((digest) => config.allowedCerts.indexOf(digest) !== -1)) {
    send(response, 200, { ok: false, reason: 'cert_mismatch' });
    return;
  }

  const rank = Object.prototype.hasOwnProperty.call(INTEGRITY_RANK, device.device_integrity_state) ? INTEGRITY_RANK[device.device_integrity_state] : -1;
  const needed = Object.prototype.hasOwnProperty.call(INTEGRITY_RANK, config.minDeviceIntegrity) ? INTEGRITY_RANK[config.minDeviceIntegrity] : 1;

  if (rank < needed) {
    send(response, 200, { ok: false, reason: 'device_not_trusted' });
    return;
  }

  if (claims.device_ban && claims.device_ban.is_banned === true) {
    send(response, 200, { ok: false, reason: 'device_banned' });
    return;
  }

  if (config.requireEntitlement && !userId) {
    send(response, 200, { ok: false, reason: 'user_required' });
    return;
  }

  try {
    if (userId && config.requireEntitlement) {
      const entitlement = await metaRequest('POST', '/' + config.metaAppId + '/verify_entitlement', { access_token: accessToken(), user_id: userId });

      if (!entitlement || entitlement.success !== true) {
        send(response, 200, { ok: false, reason: 'not_entitled' });
        return;
      }
    }

    if (userId && userProof) {
      const proof = await metaRequest('POST', '/user_nonce_validate', { access_token: accessToken(), nonce: userProof, user_id: userId });

      if (!proof || proof.is_valid !== true) {
        send(response, 200, { ok: false, reason: 'bad_user_proof' });
        return;
      }
    }
  } catch (error) {
    send(response, 200, { ok: false, reason: 'meta_unreachable' });
    return;
  }

  send(response, 200, { ok: true, receipt: makeReceipt(userId, device.unique_id) });
}

function createServer() {
  return http.createServer(async (request, response) => {
    try {
      if (request.method !== 'POST') {
        send(response, 405, { ok: false, reason: 'method_not_allowed' });
        return;
      }

      if (rateLimited(clientAddress(request))) {
        send(response, 429, { ok: false, reason: 'rate_limited' });
        return;
      }

      if (!safeEqual(request.headers['x-b4by-app-id'] || '', config.b4byAppId)) {
        send(response, 401, { ok: false, reason: 'unknown_app' });
        return;
      }

      if (request.url === '/b4by/nonce') {
        handleNonce(response);
      } else if (request.url === '/b4by/verify') {
        await handleVerify(request, response);
      } else {
        send(response, 404, { ok: false, reason: 'not_found' });
      }
    } catch (error) {
      send(response, 500, { ok: false, reason: 'server_error' });
    }
  });
}

setInterval(() => {
  const now = Date.now();

  nonces.forEach((expires, nonce) => {
    if (expires < now) {
      nonces.delete(nonce);
    }
  });

  hits.forEach((entry, address) => {
    if (entry.resetAt < now) {
      hits.delete(address);
    }
  });
}, 30000).unref();

if (require.main === module) {
  createServer().listen(config.port, () => console.log('[b4by] meta-verify listening on ' + config.port));
}

module.exports = { createServer, verifyReceipt, makeReceipt };
