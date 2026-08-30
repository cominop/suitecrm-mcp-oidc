/**
 * SuiteCRM MCP Gateway - Redis-Persisted Edition (index.mjs)
 * Hybrid v8/v4.1 bridge + Redis for sessions, profiles, and rate limiting.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { CallToolRequestSchema, ListToolsRequestSchema, ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { randomUUID, randomBytes } from 'crypto';
import { readFileSync } from 'fs';
import { execFile } from 'child_process';
import { promisify } from 'util';
import express from 'express';
const execFileAsync = promisify(execFile);
import { rateLimit, ipKeyGenerator } from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';
import https from 'https';
import http from 'http';
import { Registry, Counter, Histogram, Gauge, collectDefaultMetrics } from 'prom-client';
import pino from 'pino';

// logger is declared after PREFIX is set (see Config section below)

import { LegacyBridge } from './bridges/legacy.mjs';
import { GraphQLBridge } from './bridges/graphql.mjs';
import { HybridBridge } from './bridges/hybrid.mjs';
import { redis } from './redis.mjs';
import { initAclDb, isAclDenied, ACTION_MAP } from './acl-check.mjs';
import { writeAuditEvent } from './audit-db.mjs';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const REQUIRED = ['SUITECRM_ENDPOINT', 'SUITECRM_PREFIX', 'PORT'];
const missing = REQUIRED.filter(k => !process.env[k]);
if (missing.length) { console.error(`Missing required env vars: ${missing.join(', ')}`); process.exit(1); }

const ENDPOINT       = process.env.SUITECRM_ENDPOINT.trim();
const API_STRATEGY   = process.env.SUITECRM_API_VERSION || '4';
const CLIENT_ID      = (process.env.SUITECRM_CLIENT_ID    || '').trim();
const CLIENT_SECRET  = (process.env.SUITECRM_CLIENT_SECRET || '').trim();
const AUTH_ENDPOINT_OVERRIDE = (process.env.SUITECRM_AUTH_ENDPOINT || '').trim();
const PREFIX         = process.env.SUITECRM_PREFIX.trim();
const logger = pino({ base: { entity: PREFIX, strategy: process.env.SUITECRM_API_VERSION || '4' }, timestamp: pino.stdTimeFunctions.isoTime }, process.stderr);
const PORT           = parseInt(process.env.PORT, 10);
const CODE           = (process.env.SUITECRM_CODE || '').trim();
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE ? process.env.AUTH0_AUDIENCE.trim() : '';
const REQUIRED_GROUP = (process.env.REQUIRED_GROUP || '').trim();
const NS             = AUTH0_AUDIENCE ? AUTH0_AUDIENCE + '/' : '';
const GROUPS_CLAIM   = process.env.OAUTH_GROUPS_CLAIM || (AUTH0_AUDIENCE ? NS + 'groups' : 'groups');
const TLS_OK         = process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0';
const METRICS_PORT   = parseInt(process.env.METRICS_PORT || '9090', 10);
const METRICS_BIND   = (process.env.METRICS_BIND || '127.0.0.1').trim();
const CRM_TIMEOUT    = parseInt(process.env.CRM_TIMEOUT_MS || '30000', 10);
const CB_THRESHOLD        = parseInt(process.env.CIRCUIT_BREAKER_THRESHOLD || '5', 10);
const CB_RESET_MS         = parseInt(process.env.CIRCUIT_BREAKER_RESET_MS || '60000', 10);
const CB_INFRA_THRESHOLD  = parseInt(process.env.CB_INFRA_THRESHOLD || '10', 10);
const CB_PROBE_INTERVAL_MS = parseInt(process.env.CB_PROBE_INTERVAL_MS || '30000', 10);
const CRM_SESSION_TTL_SEC = 30 * 24 * 3600; // 30 days - matches SuiteCRM OAuth token and gateway session lifetime

const NETWORK_ERRS = new Set(['ECONNRESET','ECONNREFUSED','ETIMEDOUT','ENOTFOUND','ECONNABORTED']);
const CRM_HOSTS_FILE = '/etc/suitecrm-mcp/crm-hosts.json';
initAclDb(); // no-op if SUITECRM_DB_HOST not set

// ---------------------------------------------------------------------------
// Prometheus Metrics
// ---------------------------------------------------------------------------
const metricsRegistry = new Registry();
metricsRegistry.setDefaultLabels({ entity: PREFIX });
collectDefaultMetrics({ register: metricsRegistry });

const metricActiveConnections   = new Gauge({ name: 'suitecrm_mcp_active_connections', help: 'Active SSE connections', labelNames: ['entity'], registers: [metricsRegistry] });
const metricConnections         = new Counter({ name: 'suitecrm_mcp_connections_total', help: 'Total SSE connections', labelNames: ['entity'], registers: [metricsRegistry] });
const metricToolCalls           = new Counter({ name: 'suitecrm_mcp_tool_calls_total', help: 'Total tool calls', labelNames: ['entity','tool','status'], registers: [metricsRegistry] });
const metricToolDuration        = new Histogram({ name: 'suitecrm_mcp_tool_duration_seconds', help: 'Tool duration', labelNames: ['entity','tool'], buckets: [0.05,0.1,0.25,0.5,1,2.5,5,10], registers: [metricsRegistry] });
const metricCrmApiDuration      = new Histogram({ name: 'suitecrm_mcp_crm_api_duration_seconds', help: 'CRM API duration', labelNames: ['entity','method'], buckets: [0.05,0.1,0.25,0.5,1,2.5,5,10,30], registers: [metricsRegistry] });
const metricSessionRenewals     = new Counter({ name: 'suitecrm_mcp_session_renewals_total', help: 'CRM session renewals', labelNames: ['entity'], registers: [metricsRegistry] });
const metricAuthFailures        = new Counter({ name: 'suitecrm_mcp_auth_failures_total', help: 'Auth failures', labelNames: ['entity'], registers: [metricsRegistry] });
const metricCircuitBreakerState = new Gauge({ name: 'suitecrm_mcp_circuit_breaker_state', help: 'CB state (0=closed,1=half-open,2=open)', labelNames: ['entity'], registers: [metricsRegistry] });
const metricCircuitBreakerOpenings = new Counter({ name: 'suitecrm_mcp_circuit_breaker_openings_total', help: 'CB openings', labelNames: ['entity'], registers: [metricsRegistry] });
const metricRateLimited         = new Counter({ name: 'suitecrm_mcp_rate_limited_total', help: 'Rate limited requests', labelNames: ['entity','route'], registers: [metricsRegistry] });
const metricConnectionRejected  = new Counter({ name: 'suitecrm_mcp_connection_rejected_total', help: 'Rejected SSE connections', labelNames: ['entity'], registers: [metricsRegistry] });
const metricCrmErrors           = new Counter({ name: 'suitecrm_mcp_crm_errors_total', help: 'CRM errors', labelNames: ['entity','method','crm_code'], registers: [metricsRegistry] });
const metricCrmSessionsCached   = new Counter({ name: 'suitecrm_mcp_crm_sessions_cached', help: 'CRM sessions written to Redis (total)', labelNames: ['entity'], registers: [metricsRegistry] });

new Gauge({
  name: 'suitecrm_mcp_profiles_configured',
  help: 'Number of user profiles configured for this entity',
  labelNames: ['entity'],
  registers: [metricsRegistry],
  async collect() {
    this.reset();
    try {
      const all = await redis.hgetall('crm:profiles');
      if (!all) { this.set({ entity: PREFIX }, 0); return; }
      let count = 0;
      for (const raw of Object.values(all)) {
        try { const p = JSON.parse(raw); if (p?.entities?.[CODE]) count++; } catch (err) { logger.error({ err: err.message }, 'profile_parse_error'); }
      }
      this.set({ entity: PREFIX }, count);
    } catch { this.set({ entity: PREFIX }, 0); }
  },
});

new Gauge({
  name: 'suitecrm_mcp_user_crm_session_active',
  help: '1 if the user has an active CRM session cached in Redis for this entity',
  labelNames: ['entity', 'email'],
  registers: [metricsRegistry],
  async collect() {
    this.reset();
    try {
      const keys = await (async () => {
        const out = []; let cursor = '0';
        do { const [next, batch] = await redis.scan(cursor, 'MATCH', `crm:session:*:${CODE}`, 'COUNT', 100); out.push(...batch); cursor = next; } while (cursor !== '0');
        return out;
      })();
      const allProfiles = await redis.hgetall('crm:profiles') || {};
      for (const key of keys) {
        const sub = key.slice('crm:session:'.length, -(`:${CODE}`.length));
        const profileRaw = allProfiles[sub];
        const email = profileRaw ? (JSON.parse(profileRaw)?.email || sub) : sub;
        this.set({ entity: PREFIX, email }, 1);
      }
    } catch (err) { logger.error({ err: err.message }, 'metric_collection_error'); }
  },
});

new Gauge({
  name: 'suitecrm_mcp_user_gateway_session_active',
  help: '1 if the user currently has an active SSE connection to this entity',
  labelNames: ['entity', 'email'],
  registers: [metricsRegistry],
  collect() {
    this.reset();
    const seen = new Set();
    for (const { email } of connAuth.values()) {
      if (!seen.has(email)) { seen.add(email); this.set({ entity: PREFIX, email }, 1); }
    }
  },
});

new Gauge({
  name: 'suitecrm_mcp_gateway_sessions_active',
  help: 'Users with a valid non-expired gateway API session for this entity',
  labelNames: ['entity'],
  registers: [metricsRegistry],
  async collect() {
    this.reset();
    try {
      const sessionKeys = [];
      let cursor = '0';
      do {
        const [next, batch] = await redis.scan(cursor, 'MATCH', 'auth:session:*', 'COUNT', 100);
        sessionKeys.push(...batch);
        cursor = next;
      } while (cursor !== '0');

      const sessionData = sessionKeys.length ? await redis.mget(...sessionKeys) : [];

      const allProfiles = await redis.hgetall('crm:profiles') || {};

      const now = Date.now();
      const activeEmails = new Set();

      for (const data of sessionData) {
        if (data) {
          try {
            const session = JSON.parse(data);
            if (session.expiresAt > now) {
              activeEmails.add(session.email);
            }
          } catch { /* skip corrupt session */ }
        }
      }

      let count = 0;
      for (const [email, profileRaw] of Object.entries(allProfiles)) {
        try {
          const profile = JSON.parse(profileRaw);
          if (profile?.entities?.[CODE] && activeEmails.has(email)) {
            count++;
          }
        } catch { /* skip corrupt profile */ }
      }

      this.set({ entity: PREFIX }, count);
    } catch (err) { logger.error({ err: err.message }, 'gateway_sessions_metric_error'); this.set({ entity: PREFIX }, 0); }
  },
});

// ---------------------------------------------------------------------------
// Transport map (must stay in-process - SSE streams cannot live in Redis)
// ---------------------------------------------------------------------------
const transports  = new Map(); // sid -> SSEServerTransport
const connCreds   = new Map(); // sid -> { user, pass }
const connLoggers = new Map(); // sid -> pino child logger
const connAuth    = new Map(); // sid -> { sub, email }
const emailSids   = new Map(); // email -> Set<sid>  (all live connections per user)

// ---------------------------------------------------------------------------
// Redis-backed state helpers (replaces in-memory Maps)
// ---------------------------------------------------------------------------

// Auth sessions: look up token in Redis; null if missing or Redis is down.
async function getAuthSession(token) {
  try {
    const raw = await redis.get(`auth:session:${token}`);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

// CRM sessions (v4 sessionId + v8 token per user:entity)
async function getCrmSession(email) {
  try {
    const raw = await redis.get(`crm:session:${email}:${CODE}`);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}
async function setCrmSession(email, sessions) {
  await redis.setex(`crm:session:${email}:${CODE}`, CRM_SESSION_TTL_SEC, JSON.stringify(sessions));
}
async function delCrmSession(email) {
  await redis.del(`crm:session:${email}:${CODE}`);
}

// Connection maps (email <-> sid)
async function getEmailBySid(sid)    { return redis.get(`crm:sid2email:${sid}`);  }
async function getSidByEmail(email)  { return redis.get(`crm:email2sid:${email}`);  }
async function setEmailSidMapping(email, sid) {
  await Promise.all([
    redis.setex(`crm:email2sid:${email}`, 86400, sid),
    redis.setex(`crm:sid2email:${sid}`, 3600, email),  // 1h - timing-race zombies expire quickly
  ]);
}
async function delEmailSidMapping(email, sid) {
  // Only remove the sid→email reverse lookup; email→sid already points to the newest sid
  await redis.del(`crm:sid2email:${sid}`);
}

// Startup cleanup: delete crm:sid2email:* entries that are no longer the authoritative sid for their email.
// This eliminates zombies left by the previous process run (or a reconnect storm timing race).
async function cleanupOrphanSidMappings() {
  try {
    // Collect all valid (email → current_sid) pairs from the authoritative email2sid keys
    const email2sidKeys = [];
    let cursor = '0';
    do {
      const [next, batch] = await redis.scan(cursor, 'MATCH', 'crm:email2sid:*', 'COUNT', 100);
      email2sidKeys.push(...batch); cursor = next;
    } while (cursor !== '0');
    const validSids = new Set();
    if (email2sidKeys.length) {
      const vals = await redis.mget(...email2sidKeys);
      for (const v of vals) { if (v) validSids.add(v); }
    }

    // Scan all sid2email entries and delete any whose sid is not in validSids
    const sid2emailKeys = [];
    cursor = '0';
    do {
      const [next, batch] = await redis.scan(cursor, 'MATCH', 'crm:sid2email:*', 'COUNT', 100);
      sid2emailKeys.push(...batch); cursor = next;
    } while (cursor !== '0');
    const orphans = sid2emailKeys.filter(k => !validSids.has(k.slice('crm:sid2email:'.length)));
    if (orphans.length) {
      await redis.del(...orphans);
      logger.info({ count: orphans.length }, 'startup_orphan_sid_cleanup');
    }
  } catch (err) { logger.warn({ err: err.message }, 'startup_orphan_sid_cleanup_failed'); }
}

// User profiles (was user-profiles.json)
async function getProfile(email) {
  try {
    const raw = await redis.hget('crm:profiles', email);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

function redactAuditArgs(args) {
  const safe = {};
  for (const [k, v] of Object.entries(args)) {
    if (['name_value_list','search_params','fields'].includes(k))
      safe[k] = (typeof v === 'object' && v !== null) ? Object.fromEntries(Object.keys(v).map(fk => [fk, '[redacted]'])) : '[redacted]';
    else if (['query','search_query','search_string'].includes(k)) safe[k] = '[redacted]';
    else safe[k] = v;
  }
  return safe;
}

// ---------------------------------------------------------------------------
// Circuit Breaker
// ---------------------------------------------------------------------------
let _probeTimer = null;
function startProbe() {
  if (_probeTimer) return;
  _probeTimer = setInterval(async () => {
    if (circuitBreaker.state === 'CLOSED') { stopProbe(); return; }
    try {
      const body = 'method=get_server_info&input_type=JSON&response_type=JSON&rest_data=%7B%7D';
      await new Promise((resolve, reject) => {
        const p = new URL(V4_ENDPOINT); const lib = p.protocol === 'https:' ? https : http;
        const r = lib.request({ hostname: p.hostname, port: p.port || (p.protocol === 'https:' ? 443 : 80), path: p.pathname, method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }, rejectUnauthorized: TLS_OK }, (res) => {
          let raw = ''; res.on('data', c => raw += c);
          res.on('end', () => { try { JSON.parse(raw); resolve(); } catch { reject(new Error(`Non-JSON: ${raw.slice(0, 100)}`)); } });
        });
        r.setTimeout(5000, () => r.destroy(new Error('timeout')));
        r.on('error', reject); r.write(body); r.end();
      });
      logger.info('cb_probe_succeeded');
      crm.v4Healthy = true;
      circuitBreaker.recordSuccess();
    } catch (err) {
      logger.warn({ err: err.message }, 'cb_probe_failed');
    }
  }, CB_PROBE_INTERVAL_MS);
}
function stopProbe() {
  if (_probeTimer) { clearInterval(_probeTimer); _probeTimer = null; }
}

const circuitBreaker = {
  state: 'CLOSED', failures: 0, infraFailures: 0, lastFailure: 0,
  isOpen() {
    if (this.state === 'CLOSED') return false;
    if (this.state === 'HALF_OPEN') return true;
    if (Date.now() - this.lastFailure > CB_RESET_MS) { this.state = 'HALF_OPEN'; metricCircuitBreakerState.set({ entity: PREFIX }, 1); logger.warn({ state: 'HALF_OPEN' }, 'circuit_breaker_state'); return false; }
    return true;
  },
  recordSuccess() {
    if (this.state !== 'CLOSED') { logger.info({ state: 'CLOSED' }, 'circuit_breaker_state'); stopProbe(); }
    this.state = 'CLOSED'; this.failures = 0; this.infraFailures = 0; metricCircuitBreakerState.set({ entity: PREFIX }, 0);
  },
  recordFailure(err) {
    const isInfra = err && (err.message?.startsWith('Non-JSON') || NETWORK_ERRS.has(err.code));
    if (isInfra) {
      this.infraFailures++; this.lastFailure = Date.now();
      if (this.infraFailures < CB_INFRA_THRESHOLD && this.state !== 'OPEN') return;
    } else {
      this.failures++; this.lastFailure = Date.now();
    }
    if (this.state === 'HALF_OPEN' || ((this.failures >= CB_THRESHOLD || this.infraFailures >= CB_INFRA_THRESHOLD) && this.state !== 'OPEN')) {
      this.state = 'OPEN'; metricCircuitBreakerState.set({ entity: PREFIX }, 2); metricCircuitBreakerOpenings.inc({ entity: PREFIX });
      logger.warn({ state: 'OPEN', failures: this.failures, infraFailures: this.infraFailures }, 'circuit_breaker_state');
      startProbe();
    }
  },
};

// ---------------------------------------------------------------------------
// Bridge Initialization
// ---------------------------------------------------------------------------
const bridgeOptions = {
  logger, tlsOk: TLS_OK, timeout: CRM_TIMEOUT,
  metrics: {
    startTimer: (labels) => metricCrmApiDuration.startTimer({ entity: PREFIX, ...labels }),
    recordError: (method, err) => {
      const crmCode = typeof err.code === 'number' ? String(err.code) : (NETWORK_ERRS.has(err.code) || err.message?.includes('Timeout') ? 'network' : 'unknown');
      metricCrmErrors.inc({ entity: PREFIX, method, crm_code: crmCode });
    }
  }
};

let V4_ENDPOINT, _v8AuthEndpoint;
if (API_STRATEGY === '8') {
  if (!ENDPOINT.includes('/api/graphql')) {
    console.error('SUITECRM_ENDPOINT must be the GraphQL URL (.../api/graphql) when SUITECRM_API_VERSION=8');
    process.exit(1);
  }
  const _base = ENDPOINT.replace(/\/api\/graphql.*$/, '');
  V4_ENDPOINT      = `${_base}/legacy/service/v4_1/rest.php`;
  _v8AuthEndpoint  = AUTH_ENDPOINT_OVERRIDE || `${_base}/legacy/Api/access_token`;
} else {
  V4_ENDPOINT     = ENDPOINT; // already the v4.1 REST URL
  _v8AuthEndpoint = null;
}
const v4  = new LegacyBridge(V4_ENDPOINT, bridgeOptions);
const v8g = new GraphQLBridge(ENDPOINT, { ...bridgeOptions, authEndpoint: _v8AuthEndpoint, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
const crm = new HybridBridge(v8g, v4, { logger, priority: API_STRATEGY === '8' ? 'v8' : 'v4' });

// ---------------------------------------------------------------------------
// Auto-Provisioning
// ---------------------------------------------------------------------------
function loadCrmHosts() {
  try { return JSON.parse(readFileSync(CRM_HOSTS_FILE, 'utf8')); } catch { return null; }
}

function deriveUsername(email) {
  return (email || '').split('@')[0].toLowerCase().replace(/[^a-z0-9._-]/g, '').slice(0, 60);
}

async function autoProvisionUser(email) {
  const hosts = loadCrmHosts();
  if (!hosts?.[CODE]) throw new Error(`No SSH config for entity ${CODE} in crm-hosts.json`);
  const host = hosts[CODE];
  const username = deriveUsername(email);
  if (!username) throw new Error('Cannot derive CRM username from email');
  const password = randomBytes(16).toString('hex');
  const sshArgs = [
    '-i', host.ssh_key || '/etc/suitecrm-mcp/crm-ssh-key',
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', 'UserKnownHostsFile=/dev/null',
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=15',
    `${host.ssh_user}@${host.ssh_host}`,
    host.command,
    username,
    password,
  ];
  logger.info({ entity: CODE, ssh_host: host.ssh_host, crm_user: username, email }, 'auto_provision_start');
  const { stderr } = await execFileAsync('ssh', sshArgs, { timeout: 30000 }).catch(err => {
    throw new Error(`SSH provision failed: ${err.message}${err.stderr ? ` - ${err.stderr.trim().slice(0, 200)}` : ''}`);
  });
  if (stderr) logger.warn({ entity: CODE, crm_user: username, stderr: stderr.slice(0, 200) }, 'auto_provision_stderr');
  logger.info({ entity: CODE, crm_user: username }, 'auto_provision_success');
  const lockKey = `crm:provision-lock:${email}`;
  const locked = await redis.set(lockKey, '1', 'NX', 'EX', 30);
  if (!locked) throw new Error('Provision already in progress for this user');
  try {
    const raw = await redis.hget('crm:profiles', email);
    const profile = raw ? JSON.parse(raw) : { email, entities: {} };
    if (!profile.entities) profile.entities = {};
    profile.entities[CODE] = { user: username, pass: password };
    await redis.hset('crm:profiles', email, JSON.stringify(profile));
  } finally {
    await redis.del(lockKey);
  }
  return { user: username, pass: password };
}

// ---------------------------------------------------------------------------
// Middlewares (all async - Redis I/O)
// ---------------------------------------------------------------------------
async function jwtMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
  if (!token) return res.status(401).json({ error: 'Bearer token required' });
  try {
    const session = await getAuthSession(token);
    if (session) {
      if (session.expiresAt < Date.now()) {
        metricAuthFailures.inc({ entity: PREFIX });
        logger.warn({ reason: 'session_expired', sub: session.sub }, 'auth_failed');
        writeAuditEvent({ ts: new Date().toISOString(), email: 'unknown', entity: CODE, tool: '', module: null, msg: 'auth_failed', err: `session_expired: ${session.sub}`, reqId: null });
        return res.status(401).json({ error: 'Session expired' });
      }
      req.auth = { sub: session.sub, email: session.email, [GROUPS_CLAIM]: session.groups || [] };
      return next();
    }
  } catch (err) { return next(err); }
  metricAuthFailures.inc({ entity: PREFIX });
  logger.warn({ reason: 'invalid_token' }, 'auth_failed');
  writeAuditEvent({ ts: new Date().toISOString(), email: 'unknown', entity: CODE, tool: '', module: null, msg: 'auth_failed', err: 'invalid_token', reqId: null });
  return res.status(401).json({ error: 'Invalid token' });
}

async function profileMiddleware(req, res, next) {
  try {
    let profile = await getProfile(req.auth.email);
    if (!profile) {
      // Auto-create bare profile; entity credentials are provisioned by groupAccessMiddleware
      profile = { email: req.auth.email, entities: {} };
      await redis.hset('crm:profiles', req.auth.email, JSON.stringify(profile));
      logger.info({ email: req.auth.email }, 'profile_auto_created');
    }
    req.crmProfile = profile;
    return next();
  } catch (err) { return next(err); }
}

async function groupAccessMiddleware(req, res, next) {
  try {
    if (REQUIRED_GROUP) {
      const groups = req.auth[GROUPS_CLAIM] || [];
      if (!groups.some(g => g.toLowerCase() === REQUIRED_GROUP.toLowerCase()))
        return res.status(403).json({ error: `Not in group "${REQUIRED_GROUP}"`, your_groups: groups });
    }
    const creds = req.crmProfile?.entities?.[CODE];
    if (!creds?.user || !creds?.pass) {
      logger.info({ entity: CODE, email: req.auth.email }, 'auto_provision_triggered');
      const newCreds = await autoProvisionUser(req.auth.email);
      req.crmProfile.entities[CODE] = newCreds;
      req.crmCreds = newCreds;
      return next();
    }
    req.crmCreds = creds;
    return next();
  } catch (err) {
    if (err.message?.startsWith('SSH provision failed') || err.message?.startsWith('No SSH config')) {
      logger.error({ entity: CODE, email: req.auth.email, err: err.message }, 'auto_provision_failed');
      return res.status(403).json({
        error: `Auto-provisioning failed for ${CODE}: ${err.message}`,
        fix: `Run: mcp-admin add --sub "${req.auth.sub}" --entity ${CODE} --user <crmUser> --pass <crmPass>`,
      });
    }
    return next(err);
  }
}

// ---------------------------------------------------------------------------
// Session Lifecycle
// ---------------------------------------------------------------------------
const crmLoginInflight = new Map(); // email -> Promise - prevents parallel logins creating duplicate SuiteCRM tokens

async function ensureCrmSession(sid) {
  // connAuth is authoritative for live connections; Redis is fallback for edge cases
  const email = connAuth.get(sid)?.email ?? await getEmailBySid(sid);
  if (!email) throw new Error(`Cannot resolve user for session ${sid.slice(0, 8)} - connection may have been evicted`);
  const cached = await getCrmSession(email);
  if (cached) {
    // Proactively refresh the v8 access token if it expires within 10 minutes,
    // so we never create a new SuiteCRM OAuth token for an already-authenticated user.
    const v8 = cached.v8;
    if (v8 && typeof v8 === 'object' && v8.refreshToken && v8.expiresAt) {
      const REFRESH_BUFFER_MS = 10 * 60 * 1000;
      if (v8.expiresAt - Date.now() < REFRESH_BUFFER_MS) {
        if (crmLoginInflight.has(email)) return crmLoginInflight.get(email);
        const refreshPromise = v8g.refreshAccess(v8)
          .then(async refreshed => {
            cached.v8 = refreshed;
            await setCrmSession(email, cached);
            logger.info('v8_token_refreshed');
            return getCrmSession(email);
          })
          .catch(async err => {
            logger.warn({ err: err.message }, 'v8_token_refresh_failed');
            // Refresh failed - delete so next call does a full re-login
            await delCrmSession(email);
            throw err;
          })
          .finally(() => crmLoginInflight.delete(email));
        crmLoginInflight.set(email, refreshPromise);
        return refreshPromise;
      }
    }
    return cached;
  }

  // Deduplicate: if a login is already in flight for this user, piggyback on it
  if (crmLoginInflight.has(email)) return crmLoginInflight.get(email);

  const creds = connCreds.get(sid);
  if (!creds) throw new Error('No credentials for session');

  const promise = crm.login(creds.user, creds.pass)
    .then(async sessions => {
      await setCrmSession(email, sessions);
      metricCrmSessionsCached.inc({ entity: PREFIX });
      return sessions;
    })
    .finally(() => crmLoginInflight.delete(email));

  crmLoginInflight.set(email, promise);
  return promise;
}

async function resilientCall(sid, method, params) {
  if (circuitBreaker.isOpen()) throw new Error(`Circuit breaker open (${circuitBreaker.failures} failures)`);
  let sessions;
  try { sessions = await ensureCrmSession(sid); }
  catch (err) { circuitBreaker.recordFailure(err); throw err; }
  try {
    const result = await crm[method](sessions, params);
    circuitBreaker.recordSuccess();
    return result;
  } catch (err) {
    const isExpired = err.code === 11 || (err.message && err.message.toLowerCase().includes('expired'));
    if (isExpired) {
      metricSessionRenewals.inc({ entity: PREFIX });
      const email = connAuth.get(sid)?.email ?? await getEmailBySid(sid);
      if (!email) throw new Error(`Cannot resolve user for session ${sid.slice(0, 8)} - connection may have been evicted`);
      // Try refreshing the v8 access token before falling back to a full re-login
      // (which would create a new SuiteCRM OAuth token entry)
      const cached = await getCrmSession(email);
      if (cached?.v8?.refreshToken) {
        try {
          let refreshed;
          if (crmLoginInflight.has(email)) {
            refreshed = await crmLoginInflight.get(email);
          } else {
            const p = v8g.refreshAccess(cached.v8)
              .then(async r => {
                const updated = { ...cached, v8: r };
                await setCrmSession(email, updated);
                logger.info('v8_token_refreshed_on_expiry');
                return getCrmSession(email);
              })
              .finally(() => crmLoginInflight.delete(email));
            crmLoginInflight.set(email, p);
            refreshed = await p;
          }
          if (refreshed) {
            const result = await crm[method](refreshed, params);
            circuitBreaker.recordSuccess();
            return result;
          }
        } catch (refreshErr) {
          logger.warn({ err: refreshErr.message }, 'v8_token_refresh_failed_fallback_relogin');
          crmLoginInflight.delete(email);
        }
      }
      await delCrmSession(email);
      try {
        sessions = await ensureCrmSession(sid);
        const result = await crm[method](sessions, params);
        circuitBreaker.recordSuccess();
        return result;
      } catch (retryErr) { circuitBreaker.recordFailure(retryErr); throw retryErr; }
    }
    circuitBreaker.recordFailure(err); throw err;
  }
}
// ---------------------------------------------------------------------------
// Validation Helpers
// ---------------------------------------------------------------------------
const MODULE_RE = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const IDENT_RE  = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const UUID_RE   = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_QUERY_LEN = 2000; const MAX_ORDER_BY_LEN = 200; const MAX_RESULTS_CAP = 100; const MAX_FIELDS = 50;
function validateModule(m)    { if (!m || !MODULE_RE.test(m)) throw new McpError(ErrorCode.InvalidParams, `Invalid module: ${m}`); }
function validateId(id)       { if (!id || !UUID_RE.test(String(id))) throw new McpError(ErrorCode.InvalidParams, `Invalid UUID: ${id}`); }
function validateIdent(n, l='field') { if (!n || !IDENT_RE.test(String(n))) throw new McpError(ErrorCode.InvalidParams, `Invalid ${l}: ${n}`); }
function validateFieldList(f) { if (!Array.isArray(f)) return; if (f.length > MAX_FIELDS) throw new McpError(ErrorCode.InvalidParams, `Too many fields (max ${MAX_FIELDS})`); for (const x of f) validateIdent(x,'field'); }
function validateQuery(q)     { if (q == null) return; if (typeof q !== 'string') throw new McpError(ErrorCode.InvalidParams,'query must be a string'); if (q.length > MAX_QUERY_LEN) throw new McpError(ErrorCode.InvalidParams,`Query too long (max ${MAX_QUERY_LEN})`); }
function validateOrderBy(o)   { if (o == null) return; if (typeof o !== 'string') throw new McpError(ErrorCode.InvalidParams,'order_by must be a string'); if (o.length > MAX_ORDER_BY_LEN) throw new McpError(ErrorCode.InvalidParams,`order_by too long`); }
function validateFieldsObject(f) { if (!f || typeof f !== 'object' || Array.isArray(f)) throw new McpError(ErrorCode.InvalidParams,'fields must be a non-null object'); const keys=Object.keys(f); if (keys.length>MAX_FIELDS) throw new McpError(ErrorCode.InvalidParams,`Too many fields (max ${MAX_FIELDS})`); for (const k of keys) validateIdent(k,'field'); }
function coerceNumeric(val, def, min, max) { const n = Number.isInteger(val) ? val : parseInt(val,10); if (!Number.isFinite(n)) return def; return Math.max(min,Math.min(max,n)); }

// ---------------------------------------------------------------------------
// Tool Handlers
// ---------------------------------------------------------------------------
async function searchRecords(sid,args)     { validateModule(args.module); validateQuery(args.query); validateOrderBy(args.order_by); validateFieldList(args.fields); args.max_results=coerceNumeric(args.max_results,20,1,MAX_RESULTS_CAP); args.offset=coerceNumeric(args.offset,0,0,1000000); return resilientCall(sid,'searchRecords',args); }
async function searchText(sid,args)        { validateQuery(args.search_string); if(args.modules!==undefined){if(!Array.isArray(args.modules)||args.modules.length===0)throw new McpError(ErrorCode.InvalidParams,'modules must be a non-empty array');if(args.modules.length>20)throw new McpError(ErrorCode.InvalidParams,'modules array exceeds max 20');for(const m of args.modules)validateModule(m);} args.max_results=coerceNumeric(args.max_results,10,1,MAX_RESULTS_CAP); return resilientCall(sid,'searchText',args); }
async function getRecord(sid,args)         { validateModule(args.module); validateId(args.id); validateFieldList(args.fields); return resilientCall(sid,'getRecord',args); }
async function createRecord(sid,args)      { validateModule(args.module); validateFieldsObject(args.fields); return resilientCall(sid,'createRecord',args); }
async function updateRecord(sid,args)      { validateModule(args.module); validateId(args.id); validateFieldsObject(args.fields); return resilientCall(sid,'updateRecord',args); }
async function deleteRecord(sid,args)      { validateModule(args.module); validateId(args.id); return resilientCall(sid,'deleteRecord',args); }
async function countRecords(sid,args)      { validateModule(args.module); validateQuery(args.query); return resilientCall(sid,'countRecords',args); }
async function getRelationships(sid,args)  { validateModule(args.module); validateId(args.id); validateIdent(args.link_field,'link_field'); validateFieldList(args.related_fields); args.max_results=coerceNumeric(args.max_results,20,1,MAX_RESULTS_CAP); args.offset=coerceNumeric(args.offset,0,0,1000000); return resilientCall(sid,'getRelationships',args); }
async function linkRecords(sid,args)       { validateModule(args.module); validateId(args.id); validateIdent(args.link_field,'link_field'); if(Array.isArray(args.related_ids)){if(args.related_ids.length>100)throw new McpError(ErrorCode.InvalidParams,'Too many related_ids (max 100)');for(const r of args.related_ids)validateId(r);} return resilientCall(sid,'linkRecords',args); }
async function unlinkRecords(sid,args)     { validateModule(args.module); validateId(args.id); validateIdent(args.link_field,'link_field'); if(Array.isArray(args.related_ids)){if(args.related_ids.length>100)throw new McpError(ErrorCode.InvalidParams,'Too many related_ids (max 100)');for(const r of args.related_ids)validateId(r);} return resilientCall(sid,'unlinkRecords',args); }
async function getModuleFields(sid,args)   { validateModule(args.module); return resilientCall(sid,'getModuleFields',args); }
async function listModules(sid)            { return resilientCall(sid,'listModules',{}); }
async function getMany(sid,args)           { validateModule(args.module); if(!Array.isArray(args.ids)||args.ids.length===0)throw new McpError(ErrorCode.InvalidParams,'ids must be non-empty'); if(args.ids.length>100)throw new McpError(ErrorCode.InvalidParams,'Too many ids (max 100)'); for(const id of args.ids)validateId(id); validateFieldList(args.fields); return resilientCall(sid,'getMany',args); }
async function bulkUpsert(sid,args)        { validateModule(args.module); if(!Array.isArray(args.records)||args.records.length===0)throw new McpError(ErrorCode.InvalidParams,'records must be non-empty'); if(args.records.length>100)throw new McpError(ErrorCode.InvalidParams,'Too many records (max 100)'); for(const r of args.records)validateFieldsObject(r); return resilientCall(sid,'bulkUpsert',args); }
async function getDropdownValues(sid,args) { if(args.dropdown_name)validateIdent(args.dropdown_name,'dropdown_name'); return resilientCall(sid,'getDropdownValues',args); }
async function getRecent(sid,args)         { if(args.modules){for(const m of args.modules)validateModule(m);} args.max_results=coerceNumeric(args.max_results,10,1,MAX_RESULTS_CAP); return resilientCall(sid,'getRecent',args); }
async function getNoteAttachment(sid,args) { validateId(args.id); return resilientCall(sid,'getNoteAttachment',args); }
async function setNoteAttachment(sid,args) { validateId(args.id); if(!args.filename||!args.file_base64)throw new McpError(ErrorCode.InvalidParams,'filename and file_base64 required'); return resilientCall(sid,'setNoteAttachment',args); }
async function getUpcomingActivities(sid)  { return resilientCall(sid,'getUpcomingActivities',{}); }
async function logCall(sid,args)           { if(!args.name||!args.date_start)throw new McpError(ErrorCode.InvalidParams,'name and date_start required'); if(args.contact_ids)for(const c of args.contact_ids)validateId(c); if(args.account_ids)for(const a of args.account_ids)validateId(a); return resilientCall(sid,'logCall',args); }
async function createTask(sid,args)        { if(!args.name)throw new McpError(ErrorCode.InvalidParams,'name required'); if(args.contact_id)validateId(args.contact_id); if(args.parent_id)validateId(args.parent_id); if(args.parent_type)validateModule(args.parent_type); return resilientCall(sid,'createTask',args); }
async function createLinkedNote(sid,args)  { if(!args.name)throw new McpError(ErrorCode.InvalidParams,'name required'); if(args.parent_id)validateId(args.parent_id); if(args.contact_id)validateId(args.contact_id); if(args.parent_type)validateModule(args.parent_type); return resilientCall(sid,'createNote',args); }
async function getRecordActivities(sid,args){ validateModule(args.module); validateId(args.id); args.max_results=coerceNumeric(args.max_results,10,1,MAX_RESULTS_CAP); if(args.types!==undefined){const v=['calls','meetings','tasks','notes'];const f=(args.types||[]).filter(t=>v.includes(t));if(f.length===0)throw new McpError(ErrorCode.InvalidParams,`types must include one of: ${v.join(', ')}`);args.types=f;} return resilientCall(sid,'getRecordActivities',args); }
async function serverInfo(sid)             { const creds=connCreds.get(sid)||{}; const sessions=await ensureCrmSession(sid).catch(()=>({})); const email=connAuth.get(sid)?.email??await getEmailBySid(sid)??sid; return { prefix:PREFIX, port:PORT, entity:CODE, endpoint:ENDPOINT, api_strategy:API_STRATEGY==='8'?'Modern (v8 + v4 Fallback)':'Legacy (v4.1)', crm_user:creds.user||'?', auth:'gateway-session', required_group:REQUIRED_GROUP, v8_session:!!sessions.v8, v4_session:!!sessions.v4, session_active:!!(await getCrmSession(email)), active_connections:transports.size, circuit_breaker:circuitBreaker.state.toLowerCase(), persistence:'redis' }; }

// ---------------------------------------------------------------------------
// Dry-run handler - returns a preview object without touching the CRM
// ---------------------------------------------------------------------------
async function handleDryRun(sid, name, args) {
  const short = name.replace(`${PREFIX}_`, '');
  if (short === 'update') {
    let current = {};
    try { current = (await getRecord(sid, { module:args.module, id:args.id }))?.record ?? {}; } catch {}
    const would_change = {};
    for (const [k, v] of Object.entries(args.fields || {})) {
      const before = current[k] ?? null;
      if (String(before) !== String(v)) would_change[k] = { before, after:v };
    }
    return { dry_run:true, action:'update', module:args.module, id:args.id, would_change };
  }
  if (short === 'delete') {
    let record = {};
    try { record = (await getRecord(sid, { module:args.module, id:args.id }))?.record ?? {}; } catch {}
    return { dry_run:true, action:'delete', module:args.module, id:args.id, would_delete:record };
  }
  if (short === 'bulk_upsert') {
    const records = args.records || [];
    const would_create = records.filter(r => !r.id);
    const would_update = records.filter(r => !!r.id);
    return { dry_run:true, action:'bulk_upsert', module:args.module, would_create_count:would_create.length, would_update_count:would_update.length, records };
  }
  if (short === 'set_note_attachment') {
    const bytes = args.file_base64 ? Math.floor(args.file_base64.length * 0.75) : 0;
    return { dry_run:true, action:'set_note_attachment', id:args.id, filename:args.filename, file_mime_type:args.file_mime_type||'application/octet-stream', estimated_size_bytes:bytes };
  }
  if (short === 'link_records' || short === 'unlink_records') {
    return { dry_run:true, action:short, module:args.module, id:args.id, link_field:args.link_field, related_ids:args.related_ids };
  }
  // create / log_call / create_task / create_note
  const { dry_run:_, ...fields } = args;
  return { dry_run:true, action:'create', would_create:fields };
}

// ---------------------------------------------------------------------------
// Tool Definitions (TOOLS)
// ---------------------------------------------------------------------------
const TOOLS = [
  { name:`${PREFIX}_search`, description:'Search records with optional SQL WHERE filter', inputSchema:{type:'object',required:['module'],properties:{module:{type:'string'},query:{type:'string'},fields:{type:'array',items:{type:'string'}},max_results:{type:'number'},offset:{type:'number'},order_by:{type:'string'}}}},
  { name:`${PREFIX}_search_text`, description:'Full-text search across multiple modules', inputSchema:{type:'object',required:['search_string'],properties:{search_string:{type:'string'},modules:{type:'array',items:{type:'string'}},max_results:{type:'number'}}}},
  { name:`${PREFIX}_get`, description:'Get a single record by UUID', inputSchema:{type:'object',required:['module','id'],properties:{module:{type:'string'},id:{type:'string'},fields:{type:'array',items:{type:'string'}}}}},
  { name:`${PREFIX}_create`, description:'Create a new record. Pass dry_run:true to preview without saving.', inputSchema:{type:'object',required:['module','fields'],properties:{module:{type:'string'},fields:{type:'object',additionalProperties:{type:'string'}},dry_run:{type:'boolean'}}}},
  { name:`${PREFIX}_update`, description:'Update an existing record. Pass dry_run:true to preview without saving.', inputSchema:{type:'object',required:['module','id','fields'],properties:{module:{type:'string'},id:{type:'string'},fields:{type:'object',additionalProperties:{type:'string'}},dry_run:{type:'boolean'}}}},
  { name:`${PREFIX}_delete`, description:'Soft-delete a record. Pass dry_run:true to preview without saving.', inputSchema:{type:'object',required:['module','id'],properties:{module:{type:'string'},id:{type:'string'},dry_run:{type:'boolean'}}}},
  { name:`${PREFIX}_count`, description:'Count records matching an optional SQL WHERE clause', inputSchema:{type:'object',required:['module'],properties:{module:{type:'string'},query:{type:'string'}}}},
  { name:`${PREFIX}_get_relationships`, description:'Get related records via a named link field', inputSchema:{type:'object',required:['module','id','link_field'],properties:{module:{type:'string'},id:{type:'string'},link_field:{type:'string'},related_fields:{type:'array',items:{type:'string'}},max_results:{type:'number'},offset:{type:'number'}}}},
  { name:`${PREFIX}_link_records`, description:'Create a relationship between records. Pass dry_run:true to preview without saving.', inputSchema:{type:'object',required:['module','id','link_field','related_ids'],properties:{module:{type:'string'},id:{type:'string'},link_field:{type:'string'},related_ids:{type:'array',items:{type:'string'}},dry_run:{type:'boolean'}}}},
  { name:`${PREFIX}_unlink_records`, description:'Remove a relationship between records. Pass dry_run:true to preview without saving.', inputSchema:{type:'object',required:['module','id','link_field','related_ids'],properties:{module:{type:'string'},id:{type:'string'},link_field:{type:'string'},related_ids:{type:'array',items:{type:'string'}},dry_run:{type:'boolean'}}}},
  { name:`${PREFIX}_get_module_fields`, description:'Get all field definitions for a module', inputSchema:{type:'object',required:['module'],properties:{module:{type:'string'}}}},
  { name:`${PREFIX}_list_modules`, description:'List all available CRM modules', inputSchema:{type:'object',properties:{}}},
  { name:`${PREFIX}_server_info`, description:'Get server status, API strategy, persistence info', inputSchema:{type:'object',properties:{}}},
  { name:`${PREFIX}_get_many`, description:'Fetch multiple records by ID list in one call', inputSchema:{type:'object',required:['module','ids'],properties:{module:{type:'string'},ids:{type:'array',items:{type:'string'},maxItems:100},fields:{type:'array',items:{type:'string'}}}}},
  { name:`${PREFIX}_bulk_upsert`, description:'Create or update multiple records. Include "id" in fields to update, omit to create. Pass dry_run:true to preview without saving.', inputSchema:{type:'object',required:['module','records'],properties:{module:{type:'string'},records:{type:'array',items:{type:'object',additionalProperties:{type:'string'}},maxItems:100},dry_run:{type:'boolean'}}}},
  { name:`${PREFIX}_get_dropdown_values`, description:'List dropdown names or get key→label values for a specific dropdown', inputSchema:{type:'object',properties:{dropdown_name:{type:'string'}}}},
  { name:`${PREFIX}_get_recent`, description:'Get recently viewed records for the current user', inputSchema:{type:'object',properties:{modules:{type:'array',items:{type:'string'}},max_results:{type:'number'}}}},
  { name:`${PREFIX}_get_note_attachment`, description:'Download a file attachment from a Notes record', inputSchema:{type:'object',required:['id'],properties:{id:{type:'string'}}}},
  { name:`${PREFIX}_set_note_attachment`, description:'Upload a base64-encoded file attachment to a Notes record. Pass dry_run:true to preview without saving.', inputSchema:{type:'object',required:['id','filename','file_base64'],properties:{id:{type:'string'},filename:{type:'string'},file_base64:{type:'string'},file_mime_type:{type:'string'},dry_run:{type:'boolean'}}}},
  { name:`${PREFIX}_get_upcoming_activities`, description:'Get upcoming calls, meetings, and tasks for current user', inputSchema:{type:'object',properties:{}}},
  { name:`${PREFIX}_log_call`, description:'Create a logged call and optionally link to contacts/accounts. Pass dry_run:true to preview without saving.', inputSchema:{type:'object',required:['name','date_start'],properties:{name:{type:'string'},status:{type:'string',enum:['Planned','Held','Not Held'],default:'Held'},direction:{type:'string',enum:['Inbound','Outbound'],default:'Outbound'},duration_hours:{type:'number',default:0},duration_minutes:{type:'number',enum:[0,15,30,45],default:15},date_start:{type:'string'},description:{type:'string'},assigned_user_id:{type:'string'},contact_ids:{type:'array',items:{type:'string'}},account_ids:{type:'array',items:{type:'string'}},dry_run:{type:'boolean'}}}},
  { name:`${PREFIX}_create_task`, description:'Create a task and optionally link to a contact/parent record. Pass dry_run:true to preview without saving.', inputSchema:{type:'object',required:['name'],properties:{name:{type:'string'},status:{type:'string',enum:['Not Started','In Progress','Completed','Pending Input','Deferred'],default:'Not Started'},priority:{type:'string',enum:['High','Medium','Low'],default:'Medium'},date_due:{type:'string'},date_start:{type:'string'},description:{type:'string'},assigned_user_id:{type:'string'},contact_id:{type:'string'},parent_type:{type:'string'},parent_id:{type:'string'},dry_run:{type:'boolean'}}}},
  { name:`${PREFIX}_create_note`, description:'Create a note and optionally link to a parent record/contact. Pass dry_run:true to preview without saving.', inputSchema:{type:'object',required:['name'],properties:{name:{type:'string'},description:{type:'string'},parent_type:{type:'string'},parent_id:{type:'string'},contact_id:{type:'string'},assigned_user_id:{type:'string'},dry_run:{type:'boolean'}}}},
  { name:`${PREFIX}_get_record_activities`, description:'Get activity history for a record', inputSchema:{type:'object',required:['module','id'],properties:{module:{type:'string'},id:{type:'string'},types:{type:'array',items:{type:'string',enum:['calls','meetings','tasks','notes']},default:['calls','meetings','tasks','notes']},max_results:{type:'number'}}}},
];

// ---------------------------------------------------------------------------
// MCP Server Factory
// ---------------------------------------------------------------------------
function createMcpServer(sid) {
  const srv = new Server({ name:`suitecrm-${PREFIX}`, version:'1.0.0' }, { capabilities:{ tools:{} } });
  srv.setRequestHandler(ListToolsRequestSchema, async () => ({ tools:TOOLS }));
  srv.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args={} } = req.params;
    const reqId = randomUUID();
    const cLog = (connLoggers.get(sid)||logger).child({ reqId });
    const callStart = Date.now();
    const end = metricToolDuration.startTimer({ entity:PREFIX, tool:name });
    cLog.info({ audit:true, tool:name, args:redactAuditArgs(args) },'tool_call');
    const _auditEmail  = connAuth.get(sid)?.email || 'unknown';
    const _auditModule = args.module || (name.endsWith('_log_call') ? 'Calls' : name.endsWith('_create_task') ? 'Tasks' : name.endsWith('_create_note') ? 'Notes' : null);
    const _toolShort   = name.startsWith(`${PREFIX}_`) ? name.slice(`${PREFIX}_`.length) : name;
    writeAuditEvent({ ts: new Date().toISOString(), email: _auditEmail, entity: CODE, tool: _toolShort, module: _auditModule, reqId, msg: 'tool_call' });
    try {
      let result;

      // ACL pre-check - queries SuiteCRM DB before forwarding to CRM.
      // [action, moduleArgField, fixedModule] - null moduleArgField + fixedModule = hardcoded module.
      // Tools with no module context (search_text, get_recent, get_upcoming_activities) are intentionally omitted.
      const aclChecks = {
        [`${PREFIX}_create`]:               [ACTION_MAP.create, 'module'],
        [`${PREFIX}_update`]:               [ACTION_MAP.update, 'module'],
        [`${PREFIX}_delete`]:               [ACTION_MAP.delete, 'module'],
        [`${PREFIX}_bulk_upsert`]:          [ACTION_MAP.update, 'module'],
        [`${PREFIX}_log_call`]:             [ACTION_MAP.create, null, 'Calls'],
        [`${PREFIX}_create_task`]:          [ACTION_MAP.create, null, 'Tasks'],
        [`${PREFIX}_create_note`]:          [ACTION_MAP.create, null, 'Notes'],
        [`${PREFIX}_set_note_attachment`]:  [ACTION_MAP.update, null, 'Notes'],
        [`${PREFIX}_link_records`]:         [ACTION_MAP.update, 'module'],
        [`${PREFIX}_unlink_records`]:       [ACTION_MAP.update, 'module'],
        [`${PREFIX}_search`]:               [ACTION_MAP.list,   'module'],
        [`${PREFIX}_count`]:                [ACTION_MAP.list,   'module'],
        [`${PREFIX}_get`]:                  [ACTION_MAP.view,   'module'],
        [`${PREFIX}_get_many`]:             [ACTION_MAP.view,   'module'],
        [`${PREFIX}_get_relationships`]:    [ACTION_MAP.view,   'module'],
        [`${PREFIX}_get_note_attachment`]:  [ACTION_MAP.view,   null, 'Notes'],
        [`${PREFIX}_get_record_activities`]:[ACTION_MAP.view,   'module'],
      };
      const aclEntry = aclChecks[name];
      if (aclEntry) {
        const [action, moduleField, fixedModule] = aclEntry;
        const module = fixedModule || (moduleField ? args[moduleField] : null);
        const crmUsername = connCreds.get(sid)?.user;
        if (crmUsername && module) {
          const denied = await isAclDenied(crmUsername, module, action, args.id || null);
          if (denied) {
            throw new McpError(
              ErrorCode.InvalidRequest,
              `Permission denied: "${crmUsername}" is not allowed to perform "${action}" on module "${module}"`
            );
          }
        }
      }

      // Dry-run intercept - fires after ACL check, before CRM bridge
      if (args.dry_run === true) {
        const dryResult = await handleDryRun(sid, name, args);
        end(); metricToolCalls.inc({entity:PREFIX,tool:name,status:'success'});
        cLog.info({audit:true,tool:name,status:'dry_run',durationMs:Date.now()-callStart},'tool_done');
        writeAuditEvent({ ts: new Date().toISOString(), email: _auditEmail, entity: CODE, tool: _toolShort, module: _auditModule, reqId, msg: 'tool_done', status: 'dry_run', durationMs: Date.now()-callStart });
        return { content:[{type:'text',text:JSON.stringify(dryResult,null,2)}] };
      }

      if      (name===`${PREFIX}_search`)                result=await searchRecords(sid,args);
      else if (name===`${PREFIX}_search_text`)           result=await searchText(sid,args);
      else if (name===`${PREFIX}_get`)                   result=await getRecord(sid,args);
      else if (name===`${PREFIX}_create`)                result=await createRecord(sid,args);
      else if (name===`${PREFIX}_update`)                result=await updateRecord(sid,args);
      else if (name===`${PREFIX}_delete`)                result=await deleteRecord(sid,args);
      else if (name===`${PREFIX}_count`)                 result=await countRecords(sid,args);
      else if (name===`${PREFIX}_get_relationships`)     result=await getRelationships(sid,args);
      else if (name===`${PREFIX}_link_records`)          result=await linkRecords(sid,args);
      else if (name===`${PREFIX}_unlink_records`)        result=await unlinkRecords(sid,args);
      else if (name===`${PREFIX}_get_module_fields`)     result=await getModuleFields(sid,args);
      else if (name===`${PREFIX}_list_modules`)          result=await listModules(sid);
      else if (name===`${PREFIX}_server_info`)           result=await serverInfo(sid);
      else if (name===`${PREFIX}_get_many`)              result=await getMany(sid,args);
      else if (name===`${PREFIX}_bulk_upsert`)           result=await bulkUpsert(sid,args);
      else if (name===`${PREFIX}_get_dropdown_values`)   result=await getDropdownValues(sid,args);
      else if (name===`${PREFIX}_get_recent`)            result=await getRecent(sid,args);
      else if (name===`${PREFIX}_get_note_attachment`)   result=await getNoteAttachment(sid,args);
      else if (name===`${PREFIX}_set_note_attachment`)   result=await setNoteAttachment(sid,args);
      else if (name===`${PREFIX}_get_upcoming_activities`) result=await getUpcomingActivities(sid);
      else if (name===`${PREFIX}_log_call`)              result=await logCall(sid,args);
      else if (name===`${PREFIX}_create_task`)           result=await createTask(sid,args);
      else if (name===`${PREFIX}_create_note`)           result=await createLinkedNote(sid,args);
      else if (name===`${PREFIX}_get_record_activities`) result=await getRecordActivities(sid,args);
      else throw new McpError(ErrorCode.MethodNotFound,`Unknown tool: ${name}`);
      end(); metricToolCalls.inc({entity:PREFIX,tool:name,status:'success'});
      cLog.info({audit:true,tool:name,status:'success',durationMs:Date.now()-callStart},'tool_done');
      const _rc = (() => { try { if (Array.isArray(result?.records)) return result.records.length; if (Array.isArray(result?.data)) return result.data.length; if (Array.isArray(result)) return result.length; if (typeof result?.total_count==='number') return result.total_count; if (typeof result?.count==='number') return result.count; } catch {} return null; })();
      writeAuditEvent({ ts: new Date().toISOString(), email: _auditEmail, entity: CODE, tool: _toolShort, module: _auditModule, reqId, msg: 'tool_done', status: 'success', durationMs: Date.now()-callStart, resultCount: _rc });
      return { content:[{type:'text',text:JSON.stringify(result,null,2)}] };
    } catch(err) {
      end(); metricToolCalls.inc({entity:PREFIX,tool:name,status:'error'});
      cLog.error({audit:true,tool:name,status:'error',err:err.message},'tool_error');
      writeAuditEvent({ ts: new Date().toISOString(), email: _auditEmail, entity: CODE, tool: _toolShort, module: _auditModule, reqId, msg: 'tool_error', status: 'error', err: err.message, durationMs: Date.now()-callStart });
      return { content:[{type:'text',text:`Error: ${err.message}`}], isError:true };
    }
  });
  return srv;
}

// ---------------------------------------------------------------------------
// Rate Limiters (Redis-backed for shared global limits)
// ---------------------------------------------------------------------------
const redisStore = (pfx) => new RedisStore({ sendCommand: (...args) => redis.call(...args), prefix:pfx });
const sseRL = rateLimit({ windowMs:60000, max:60, standardHeaders:true, legacyHeaders:false, message:{error:'Too many connection attempts - try again shortly'}, store:redisStore('rl:sse:'), keyGenerator:async(req)=>{ const token=req.headers.authorization?.startsWith('Bearer ')?req.headers.authorization.slice(7).trim():''; if(token){ const session=await getAuthSession(token); if(session?.email) return session.email; return token; } return ipKeyGenerator(req); }, handler:(req,res,next,opts)=>{ metricRateLimited.inc({entity:PREFIX,route:'sse'}); logger.warn({route:'sse'},'rate_limit_hit'); res.status(opts.statusCode).json(opts.message); } });
const messagesRL = rateLimit({ windowMs:60000, max:100, standardHeaders:true, legacyHeaders:false, message:{error:'Too many tool calls - slow down'}, store:redisStore('rl:msg:'), keyGenerator:(req)=>req.query.sessionId||ipKeyGenerator(req), handler:(req,res,next,opts)=>{ metricRateLimited.inc({entity:PREFIX,route:'messages'}); logger.warn({route:'messages'},'rate_limit_hit'); res.status(opts.statusCode).json(opts.message); } });
const deepHealthRL = rateLimit({ windowMs:60000, max:10, standardHeaders:true, legacyHeaders:false, message:{error:'Too many health check requests'}, handler:(req,res,next,opts)=>{ metricRateLimited.inc({entity:PREFIX,route:'health_deep'}); res.status(opts.statusCode).json(opts.message); } });
const healthRL = rateLimit({ windowMs:60000, max:120, standardHeaders:true, legacyHeaders:false, message:{error:'Too many health check requests'}, handler:(req,res,next,opts)=>{ res.status(opts.statusCode).json(opts.message); } });

// ---------------------------------------------------------------------------
// Express App & Routes
// ---------------------------------------------------------------------------
const app = express();
app.set('trust proxy', 1);
app.use((req,res,next) => req.path.endsWith('/messages') ? next() : express.json()(req,res,next));

app.get('/health', healthRL, (_req,res) => res.json({ status:'ok', entity:CODE, port:PORT, active:transports.size, circuit_breaker:circuitBreaker.state.toLowerCase(), persistence:'redis' }));

app.get('/health/deep', deepHealthRL, async (_req,res) => {
  const start=Date.now(); const checks={}; let status='healthy';
  try { const p=new URL(ENDPOINT); checks.endpoint={status:'ok',url:`${p.protocol}//${p.host}`}; } catch { checks.endpoint={status:'error',message:'Invalid endpoint URL'}; status='unhealthy'; }
  try { await redis.ping(); checks.redis={status:'ok'}; } catch(e) { checks.redis={status:'error',message:e.message}; status='degraded'; }
  try {
    const crmStart=Date.now();
    const body='method=get_server_info&input_type=JSON&response_type=JSON&rest_data=%7B%7D';
    const crmData = await new Promise((resolve,reject) => {
      const p=new URL(V4_ENDPOINT); const lib=p.protocol==='https:'?https:http;
      const r=lib.request({ hostname:p.hostname, port:p.port||(p.protocol==='https:'?443:80), path:p.pathname, method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(body)}, rejectUnauthorized:TLS_OK }, (res) => { if(res.statusCode<200||res.statusCode>=300){res.resume();return reject(new Error(`HTTP ${res.statusCode}`));} let raw=''; res.on('data',c=>raw+=c); res.on('end',()=>{ try{resolve(JSON.parse(raw));}catch{resolve({});} }); });
      r.setTimeout(5000,()=>r.destroy(new Error('timeout')));
      r.on('error',reject); r.write(body); r.end();
    });
    checks.v4={ status:'ok', latency_ms:Date.now()-crmStart, ...(crmData.suite_version?{version:crmData.suite_version}:{}) };
  } catch(e) { checks.v4={status:'error',message:e.message}; if(status==='healthy') status='degraded'; }
  checks.sessions={status:'ok',active:transports.size};
  if (API_STRATEGY === '8') {
    const v8Start = Date.now();
    let v8Session = null;
    for (const [, auth] of connAuth.entries()) {
      const s = auth.email ? await getCrmSession(auth.email).catch(() => null) : null;
      if (s?.v8?.token && (!s.v8.expiresAt || s.v8.expiresAt > Date.now())) { v8Session = s; break; }
    }
    if (v8Session) {
      if (crm.v8Healthy === false) {
        checks.v8 = { status: 'error', message: 'v8 auth ok but API calls failing - CSRF or permission issue on CRM' };
        if (checks.v4?.status !== 'ok' && status === 'healthy') status = 'degraded';
      } else {
        checks.v8 = { status: 'ok', latency_ms: Date.now() - v8Start, ...(crm.v8Healthy === null ? { note: 'auth_only - no tool calls yet' } : {}) };
      }
    } else {
      checks.v8 = { status: 'unknown' };
    }
  } else {
    checks.v8 = { status: 'not_configured' };
  }
  res.status(status==='unhealthy'?503:200).json({ status, entity:CODE, port:PORT, uptime:Math.floor(process.uptime()), connections:transports.size, circuit_breaker:circuitBreaker.state.toLowerCase(), api_strategy:API_STRATEGY==='8'?'Modern (v8 + v4 Fallback)':'Legacy (v4.1)', persistence:'redis', checks, duration_ms:Date.now()-start });
});

app.get('/test', sseRL, jwtMiddleware, profileMiddleware, groupAccessMiddleware, async (req,res) => {
  try { const s=await crm.login(req.crmCreds.user,req.crmCreds.pass); res.json({success:true,crm_user:req.crmCreds.user,entity:CODE,v8_session:!!s.v8,v4_session:!!s.v4}); }
  catch(err) { res.status(401).json({success:false,error:err.message}); }
});

app.get('/sse', sseRL, jwtMiddleware, profileMiddleware, groupAccessMiddleware, async (req,res) => {
  if (transports.size>=100) { metricConnectionRejected.inc({entity:PREFIX}); return res.status(503).json({error:'At capacity'}); }
  const transport=new SSEServerTransport(`${CODE?`/${CODE}`:''}/messages`,res);
  const sid=transport.sessionId;
  const srv=createMcpServer(sid);

  // Register transport, credentials, auth, and close handler SYNCHRONOUSLY before any awaits.
  // The MCP client immediately POSTs initialize to /messages after the SSE stream opens.
  // If transports.set is deferred until after Redis awaits (~20-50ms), those POSTs return
  // 404 → client drops the SSE and reconnects → eviction death-spiral.
  const prevSids = emailSids.get(req.auth.email) ?? new Set();
  emailSids.set(req.auth.email, new Set([sid]));
  connCreds.set(sid,req.crmCreds);
  connAuth.set(sid,{sub:req.auth.sub,email:req.auth.email});
  transports.set(sid,transport);
  const connLogger=logger.child({email:req.auth.email,sessionId:sid});
  connLoggers.set(sid,connLogger);

  // Close handler must also be registered synchronously so it fires even if we are
  // evicted by a concurrent reconnect during the async eviction phase below.
  res.on('close',async()=>{
    connLogger.info('sse_disconnected');
    writeAuditEvent({ ts: new Date().toISOString(), email: req.auth.email, entity: CODE, tool: '', module: null, msg: 'disconnect', reqId: sid });
    transports.delete(sid); connCreds.delete(sid); connLoggers.delete(sid); connAuth.delete(sid);
    const sids=emailSids.get(req.auth.email); if(sids){sids.delete(sid); if(sids.size===0)emailSids.delete(req.auth.email);}
    try { await delEmailSidMapping(req.auth.email,sid); } catch(err) { connLogger.error({err:err.message},'sse_close_mapping_delete_failed'); }
    metricActiveConnections.set({entity:PREFIX},transports.size);
  });

  // Evict prior connections (async Redis ops happen here)
  // Post-restart recovery: emailSids was empty, but Redis may still hold the last known sid.
  const lastRedisSid = await getSidByEmail(req.auth.email);
  if (lastRedisSid && !prevSids.has(lastRedisSid)) prevSids.add(lastRedisSid);

  const staleRedisDeletes = [];
  for (const prevSid of prevSids) {
    staleRedisDeletes.push(redis.del(`crm:sid2email:${prevSid}`).catch(() => {}));
    if (transports.has(prevSid)) {
      connLoggers.get(prevSid)?.info('sse_evicted_by_reconnect');
      transports.get(prevSid).close?.();
      transports.delete(prevSid); connCreds.delete(prevSid); connLoggers.delete(prevSid); connAuth.delete(prevSid);
    }
  }
  await Promise.all(staleRedisDeletes);

  // If a concurrent reconnect evicted us during the async phase above, abort - the newer
  // connection already owns this user's slot. Writing email2sid now would overwrite theirs.
  if (!transports.has(sid)) {
    connLogger.info('sse_aborted_evicted_during_setup');
    return;
  }

  await setEmailSidMapping(req.auth.email, sid);

  // Post-write cleanup: remove zombie sid2sub entries for this user from previous process runs.
  (async () => {
    try {
      const allKeys = []; let c = '0';
      do { const [next, batch] = await redis.scan(c, 'MATCH', 'crm:sid2email:*', 'COUNT', 100); allKeys.push(...batch); c = next; } while (c !== '0');
      if (!allKeys.length) return;
      const vals = await redis.mget(...allKeys);
      const orphans = allKeys.filter((k, i) => k !== `crm:sid2email:${sid}` && vals[i] === req.auth.email);
      if (orphans.length) { await redis.del(...orphans); logger.debug({ count: orphans.length }, 'post_connect_zombie_cleanup'); }
    } catch { /* non-fatal */ }
  })();

  connLogger.info('sse_connected');
  writeAuditEvent({ ts: new Date().toISOString(), email: req.auth.email, entity: CODE, tool: '', module: null, msg: 'connect', reqId: sid });
  metricActiveConnections.set({entity:PREFIX},transports.size);
  metricConnections.inc({entity:PREFIX});
  ensureCrmSession(sid).catch(err=>connLogger.error({crm_user:connCreds.get(sid)?.user, err:err.message},'crm_login_failed'));
  await srv.connect(transport);
  // Keepalive: ping every 20s so clients detect server restart and reconnect
  const _ping = setInterval(() => { try { res.write(':ping\n\n'); } catch { clearInterval(_ping); } }, 20000);
  res.on('close', () => clearInterval(_ping));
});

app.post('/messages', messagesRL, async (req,res) => {
  const sid=req.query.sessionId;
  const t=transports.get(sid);
  if (!t) return res.status(404).json({error:'Session not found'});
  const token=req.headers.authorization?.startsWith('Bearer ')?req.headers.authorization.slice(7).trim():'';
  if (!token) return res.status(401).json({error:'Bearer token required'});
  const session=await getAuthSession(token);
  // connAuth is authoritative for live connections; fall back to Redis only if not found in-process
  const expectedEmail = connAuth.get(sid)?.email ?? await getEmailBySid(sid);
  if (!session||!expectedEmail||session.email!==expectedEmail) return res.status(403).json({error:'Token does not match session owner'});
  if (session.expiresAt<Date.now()) return res.status(401).json({error:'Session expired'});
  // Re-check group membership on every tool call using the groups cached in the session.
  // Groups reflect state at login time; for immediate revocation delete the session via POST /auth/logout.
  if (REQUIRED_GROUP) {
    const groups = session.groups || [];
    if (!groups.some(g => g.toLowerCase() === REQUIRED_GROUP.toLowerCase())) {
      metricAuthFailures.inc({ entity: PREFIX });
      logger.warn({ sub: session.sub, reason: 'group_check_failed_on_message' }, 'auth_failed');
      writeAuditEvent({ ts: new Date().toISOString(), email: session.email, entity: CODE, tool: '', module: null, msg: 'auth_failed', err: `group_check_failed: not in "${REQUIRED_GROUP}"`, reqId: null });
      return res.status(403).json({ error: `Not in group "${REQUIRED_GROUP}"` });
    }
  }
  await t.handlePostMessage(req,res);
});

// Global error handler (catches Redis errors from async middlewares)
app.use((err,req,res,_next)=>{ logger.error({err:err.message},'middleware_error'); res.status(503).json({error:'Service temporarily unavailable'}); });

function gracefulShutdown(signal) {
  logger.info({connections:transports.size,signal},'shutdown');
  stopProbe();
  for (const [,t] of transports) t.close?.();
  const timeout = setTimeout(() => { logger.error('shutdown_timeout'); process.exit(1); }, 3000);
  redis.quit().finally(() => { clearTimeout(timeout); process.exit(0); });
}
process.on('SIGTERM',()=>gracefulShutdown('SIGTERM'));
process.on('SIGINT', ()=>gracefulShutdown('SIGINT'));

const BIND_HOST=(process.env.BIND_HOST||'127.0.0.1').trim();
// Run before accepting connections so reconnect burst starts with a clean slate
cleanupOrphanSidMappings().then(() =>
  app.listen(PORT, BIND_HOST, () => logger.info({ host: BIND_HOST, port: PORT, persistence: 'redis' }, 'server_listening'))
);

const metricsServer=http.createServer(async(req,res)=>{
  if (req.url==='/metrics'&&req.method==='GET') { res.writeHead(200,{'Content-Type':metricsRegistry.contentType}); res.end(await metricsRegistry.metrics()); }
  else { res.writeHead(404); res.end(); }
});
metricsServer.listen(METRICS_PORT,METRICS_BIND,()=>logger.info({host:METRICS_BIND,port:METRICS_PORT},'metrics_listening'));
