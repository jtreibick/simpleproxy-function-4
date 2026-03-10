import {
  htmlPage,
  escapeHtml,
  capitalize,
} from "../common/html.js";
import { parseBootstrapEnrichedHeadersJson } from "../common/bootstrap_enriched_headers.js";
import { PREPROCESSORS } from "./preprocessors.js";
import {
  HttpError,
  toHttpError,
  successEnvelope,
  errorEnvelope,
  jsonResponse,
  apiError,
  isNonArrayObject,
  isPlainObject,
  normalizeHeaderName,
  getPathValue,
  getStoredContentType,
  normalizeHeaderMap,
} from "../common/lib.js";
import { ERROR_CODES } from "../common/error_codes.js";
import {
  DEFAULT_CONFIG_V1,
  VALID_TRANSFORM_TYPES,
  createConfigApi,
  validateAndNormalizeConfigV1,
} from "../common/config.js";
import { createRequestAuthApi } from "../common/request_auth.js";
import { createJwtAuthApi } from "../common/jwt_auth.js";
import { createKeyAuthApi } from "../common/key_auth.js";
import { createTransformRuntimeApi } from "../common/transform_runtime.js";
import { createObservabilityApi } from "../common/observability.js";
import { createProxyRuntimeApi } from "./proxy_runtime.js";
import { createPlatformAdapters } from "../platform/index.js";
import { buildRuntimeRouteHandlers } from "./routes/handler_registry.js";
import {
  readRuntimeEnv,
  loadRuntimeAdminConfig,
  RUNTIME_RESERVED_ROOT,
} from "./runtime_meta.js";
import {
  createAuthProfileKeyResolvers,
} from "../common/auth_profile_keys.js";
import { createProxySupportApi } from "../common/proxy_support.js";
import { dispatchPublicRoute } from "../common/routes/public.js";
import { createRouteAuth } from "../common/routes/route_auth.js";
import {
  KV_PROXY_KEY,
  KV_ADMIN_KEY,
  KV_ISSUER_KEY,
  KV_PROXY_KEY_OLD,
  KV_PROXY_KEY_OLD_EXPIRES_AT,
  KV_PROXY_PRIMARY_KEY_CREATED_AT,
  KV_PROXY_SECONDARY_KEY_CREATED_AT,
  KV_ISSUER_KEY_OLD,
  KV_ISSUER_KEY_OLD_EXPIRES_AT,
  KV_ISSUER_PRIMARY_KEY_CREATED_AT,
  KV_ISSUER_SECONDARY_KEY_CREATED_AT,
  KV_ADMIN_KEY_OLD,
  KV_ADMIN_KEY_OLD_EXPIRES_AT,
  KV_ADMIN_PRIMARY_KEY_CREATED_AT,
  KV_ADMIN_SECONDARY_KEY_CREATED_AT,
  KV_CONFIG_YAML,
  KV_CONFIG_JSON,
  KV_ENRICHED_HEADER_PREFIX,
  KV_HTTP_SECRET_PREFIX,
  KV_BOOTSTRAP_ENRICHED_HEADER_NAMES,
  KV_DEBUG_ENABLED_UNTIL_MS,
  AUTH_PROFILE_PREFIXES,
  AUTH_PROFILE_FIELDS,
  ADMIN_ROOT,
  DEFAULT_DOCS_URL,
  DEBUG_MAX_TRACE_CHARS,
  DEBUG_MAX_BODY_PREVIEW_CHARS,
  DEFAULTS,
  EXPECTED_REQUEST_SCHEMA,
  SAFE_META_HEADERS,
  INTERNAL_AUTH_HEADERS,
  JWKS_CACHE_TTL_MS,
  BUILTIN_DEBUG_REDACT_HEADERS,
  normalizePathname,
  renderWorkerError,
  createKvHelpers,
} from "../common/worker_shared.js";

/**
 * Runtime worker.
 *
 * Endpoints:
 * - GET /                        : proxy request passthrough when X-Proxy-Key is present
 * - POST /_apiproxy/request      : authenticated relay + optional JSONata transform
 * - POST /_apiproxy/keys/proxy/rotate
 * - POST /_apiproxy/keys/issuer/rotate
 */

let jsonataFactory = null;
const RESERVED_ROOT = RUNTIME_RESERVED_ROOT;
const PLATFORM = createPlatformAdapters();

function createWorker() {
  return {
    async fetch(request, env, ctx) {
      const { pathname } = new URL(request.url);
      const normalizedPath = normalizePathname(pathname);

      try {
        const publicResponse = await dispatchPublicRoute({
          normalizedPath,
          request,
          env,
          ctx,
          reservedRoot: RESERVED_ROOT,
          handlers: routeHandlers,
          auth: routeAuth,
          options: {
            enableRootProxy: true,
            enableStatusBootstrap: false,
            enableRequest: true,
            enableProxyRotate: true,
            enableIssuerRotate: true,
            enableAdminRotate: false,
          },
        });
        if (publicResponse) return publicResponse;

        return apiError(404, ERROR_CODES.NOT_FOUND, "Route not found");
      } catch (error) {
        return renderWorkerError({
          error,
          pathname: normalizedPath,
          toHttpError,
          htmlPage,
          escapeHtml,
          apiError,
        });
      }
    },
  };
}

export default createWorker();

// Expose config validator for local tooling (not used by Worker runtime).
export { createWorker, validateAndNormalizeConfigV1 };

const { secretStore, dataStore, ensureKvBinding } = createKvHelpers({
  HttpError,
  createStorageConnector: PLATFORM.createStorageConnector,
});
const authProfileKeyResolvers = createAuthProfileKeyResolvers({
  prefixMap: AUTH_PROFILE_PREFIXES,
  secretPrefix: KV_HTTP_SECRET_PREFIX,
});

const proxySupportApi = createProxySupportApi({
  HttpError,
  getStoredContentType,
  isPlainObject,
  safeMetaHeaders: SAFE_META_HEADERS,
});
const {
  getEnvInt,
  readJsonWithLimit,
  truncateJsonSnippet,
  enforceInvokeContentType,
  validateInvokePayload,
  assertSafeUpstreamUrl,
  detectResponseType,
  readResponseWithLimit,
  decodeBody,
  parseJsonOrNull,
  toSafeUpstreamHeaders,
  resolveUpstreamUrl,
} = proxySupportApi;

const configApi = createConfigApi({
  ensureKvBinding,
  kvStore: dataStore,
  kvConfigYamlKey: KV_CONFIG_YAML,
  kvConfigJsonKey: KV_CONFIG_JSON,
});

const requestAuthApi = createRequestAuthApi({
  isNonArrayObject,
  isPlainObject,
  getPathValue,
  authProfilePrefix: authProfileKeyResolvers.authProfilePrefix,
  authProfileKvKey: authProfileKeyResolvers.authProfileKvKey,
  httpSecretKvKey: authProfileKeyResolvers.httpSecretKvKey,
  kvGetValue: (env, key) => secretStore(env).get(key),
  kvPutValue: (env, key, value) => secretStore(env).put(key, value),
  authProfileFields: AUTH_PROFILE_FIELDS,
  httpRequest: PLATFORM.http.request,
});

const jwtAuthApi = createJwtAuthApi({
  buildHttpRequestInit: requestAuthApi.buildHttpRequestInit,
  jwksCacheTtlMs: JWKS_CACHE_TTL_MS,
  nowMs: PLATFORM.clock.nowMs,
  httpRequest: PLATFORM.http.request,
  subtle: PLATFORM.crypto.subtle,
});

const keyAuthApi = createKeyAuthApi({
  constants: {
    KV_PROXY_KEY,
    KV_ADMIN_KEY,
    KV_ISSUER_KEY,
    KV_PROXY_KEY_OLD,
    KV_PROXY_KEY_OLD_EXPIRES_AT,
    KV_PROXY_PRIMARY_KEY_CREATED_AT,
    KV_PROXY_SECONDARY_KEY_CREATED_AT,
    KV_ISSUER_KEY_OLD,
    KV_ISSUER_KEY_OLD_EXPIRES_AT,
    KV_ISSUER_PRIMARY_KEY_CREATED_AT,
    KV_ISSUER_SECONDARY_KEY_CREATED_AT,
    KV_ADMIN_KEY_OLD,
    KV_ADMIN_KEY_OLD_EXPIRES_AT,
    KV_ADMIN_PRIMARY_KEY_CREATED_AT,
    KV_ADMIN_SECONDARY_KEY_CREATED_AT,
  },
  ensureKvBinding,
  secretStore,
  dataStore,
  loadConfigV1: configApi.loadConfigV1,
  loadAdminConfig: loadRuntimeAdminConfig,
  getEnvInt,
  defaults: DEFAULTS,
  reservedRoot: RESERVED_ROOT,
  generateSecret,
  parseMs,
  capitalize,
  escapeHtml,
  htmlPage,
  jsonResponse,
  signJwtHs256: jwtAuthApi.signJwtHs256,
  verifyJwtHs256: jwtAuthApi.verifyJwtHs256,
});

const transformRuntimeApi = createTransformRuntimeApi({
  isPlainObject,
  normalizeHeaderName,
  defaultHeaderForwarding: DEFAULT_CONFIG_V1.header_forwarding,
  internalAuthHeadersSet: INTERNAL_AUTH_HEADERS,
  loadJsonata,
});

const observabilityApi = createObservabilityApi({
  adminRoot: ADMIN_ROOT,
  kvDebugEnabledUntilMsKey: KV_DEBUG_ENABLED_UNTIL_MS,
  builtinDebugRedactHeaders: BUILTIN_DEBUG_REDACT_HEADERS,
  debugMaxTraceChars: DEBUG_MAX_TRACE_CHARS,
  debugMaxBodyPreviewChars: DEBUG_MAX_BODY_PREVIEW_CHARS,
  ensureKvBinding,
  kvStore: dataStore,
  normalizeHeaderMap,
  loadConfigV1: configApi.loadConfigV1,
  getEnvInt,
  defaults: DEFAULTS,
  enforceInvokeContentType,
  readJsonWithLimit,
  jsonResponse,
  htmlPage,
  escapeHtml,
  buildHttpRequestInit: requestAuthApi.buildHttpRequestInit,
  nowMs: PLATFORM.clock.nowMs,
  httpRequest: PLATFORM.http.request,
});

const proxyRuntimeApi = createProxyRuntimeApi({
  requireProxyKey: keyAuthApi.requireProxyKey,
  enforceInvokeContentType,
  readJsonWithLimit,
  getEnvInt,
  defaults: DEFAULTS,
  validateInvokePayload,
  HttpError,
  expectedRequestSchema: EXPECTED_REQUEST_SCHEMA,
  truncateJsonSnippet,
  loadConfigV1: configApi.loadConfigV1,
  defaultConfigV1: DEFAULT_CONFIG_V1,
  getDebugRedactHeaderSet: observabilityApi.getDebugRedactHeaderSet,
  isDebugEnabled: observabilityApi.isDebugEnabled,
  generateSecret,
  fmtTs: observabilityApi.fmtTs,
  toRedactedHeaderMap: observabilityApi.toRedactedHeaderMap,
  previewBodyForDebug: observabilityApi.previewBodyForDebug,
  resolveProxyHostForRequest,
  getInboundHeaderFilteringPolicy: transformRuntimeApi.getInboundHeaderFilteringPolicy,
  extractJwtFromHeaders: jwtAuthApi.extractJwtFromHeaders,
  verifyJwtRs256: jwtAuthApi.verifyJwtRs256,
  getIssuerKeyState: keyAuthApi.getIssuerKeyState,
  verifyJwtHs256: jwtAuthApi.verifyJwtHs256,
  resolveCustomHook,
  isPlainObject,
  normalizeHeaderMap,
  selectTransformRule: transformRuntimeApi.selectTransformRule,
  evalJsonataWithTimeout: transformRuntimeApi.evalJsonataWithTimeout,
  resolveUpstreamUrl,
  getAllowedHosts,
  assertSafeUpstreamUrl,
  shouldForwardIncomingHeader: transformRuntimeApi.shouldForwardIncomingHeader,
  internalAuthHeaders: INTERNAL_AUTH_HEADERS,
  loadEnrichedHeadersMap,
  isNonArrayObject,
  resolveAuthProfileHeaders: requestAuthApi.resolveAuthProfileHeaders,
  signJwtHs256: jwtAuthApi.signJwtHs256,
  readResponseWithLimit,
  getStoredContentType,
  decodeBody,
  detectResponseType,
  parseJsonOrNull,
  toSafeUpstreamHeaders,
  jsonResponse,
  errorEnvelope,
  successEnvelope,
  observabilityApi,
  buildHttpRequestInit: requestAuthApi.buildHttpRequestInit,
  validTransformTypes: VALID_TRANSFORM_TYPES,
  nowMs: PLATFORM.clock.nowMs,
  httpRequest: PLATFORM.http.request,
});

const routeHandlers = buildRuntimeRouteHandlers({
  proxyRuntimeApi,
  handleRotateByKind: keyAuthApi.handleRotateByKind,
});
const routeAuth = createRouteAuth(keyAuthApi);

function getAllowedHosts(env) {
  const runtimeEnv = readRuntimeEnv(env);
  const raw = String(runtimeEnv.allowedHosts || DEFAULTS.ALLOWED_HOSTS).trim();
  if (!raw) return null;
  return new Set(
    raw
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
  );
}

function resolveCustomHook(name) {
  const key = String(name || "").trim();
  if (!key) return null;
  const fn = PREPROCESSORS?.[key];
  return typeof fn === "function" ? fn : null;
}

function getBootstrapEnrichedHeaders(env) {
  return parseBootstrapEnrichedHeadersJson(env?.BOOTSTRAP_ENRICHED_HEADERS_JSON, env, {
    HttpError,
    isPlainObject,
    normalizeHeaderName,
  });
}

async function syncBootstrapEnrichedHeaders(env, managedHeaders) {
  ensureKvBinding(env);
  const names = Object.keys(managedHeaders || {});
  const prevRaw = await dataStore(env).get(KV_BOOTSTRAP_ENRICHED_HEADER_NAMES);
  let prev = [];
  try {
    const parsed = JSON.parse(prevRaw || "[]");
    if (Array.isArray(parsed)) prev = parsed.map((n) => normalizeHeaderName(n)).filter(Boolean);
  } catch {
    prev = [];
  }
  const prevSet = new Set(prev);
  const nextSet = new Set(names);

  const deletes = [];
  for (const name of prevSet) {
    if (!nextSet.has(name)) deletes.push(dataStore(env).delete(enrichedHeaderKvKey(name)));
  }

  const gets = await Promise.all(names.map((name) => dataStore(env).get(enrichedHeaderKvKey(name))));
  const puts = [];
  for (let i = 0; i < names.length; i += 1) {
    const name = names[i];
    const desired = managedHeaders[name];
    if (gets[i] !== desired) {
      puts.push(dataStore(env).put(enrichedHeaderKvKey(name), desired));
    }
  }

  const prevSorted = [...prevSet].sort();
  const nextSorted = [...nextSet].sort();
  const namesChanged = prevSorted.length !== nextSorted.length || prevSorted.some((n, i) => n !== nextSorted[i]);
  const ops = [...deletes, ...puts];
  if (namesChanged) {
    ops.push(dataStore(env).put(KV_BOOTSTRAP_ENRICHED_HEADER_NAMES, JSON.stringify(nextSorted)));
  }
  if (ops.length > 0) {
    await Promise.all(ops);
  }
}

async function listEnrichedHeaderNames(env, managedHeaders = null) {
  ensureKvBinding(env);
  const out = [];
  let cursor = undefined;

  while (true) {
    const page = await dataStore(env).list({
      prefix: KV_ENRICHED_HEADER_PREFIX,
      cursor,
      limit: 1000,
    });
    for (const entry of page.keys || []) {
      const key = String(entry.name || "");
      if (!key.startsWith(KV_ENRICHED_HEADER_PREFIX)) continue;
      out.push(key.slice(KV_ENRICHED_HEADER_PREFIX.length));
    }
    if (!page.list_complete) {
      cursor = page.cursor;
      continue;
    }
    break;
  }

  if (managedHeaders && isPlainObject(managedHeaders)) {
    for (const name of Object.keys(managedHeaders)) out.push(name);
  }

  return [...new Set(out)].sort();
}

async function loadEnrichedHeadersMap(env) {
  const managedHeaders = getBootstrapEnrichedHeaders(env);
  await syncBootstrapEnrichedHeaders(env, managedHeaders);
  const names = await listEnrichedHeaderNames(env, managedHeaders);
  if (names.length === 0) return {};

  const values = await Promise.all(names.map((name) => dataStore(env).get(enrichedHeaderKvKey(name))));
  const out = {};
  for (let i = 0; i < names.length; i += 1) {
    const value = values[i];
    if (typeof value === "string") out[names[i]] = value;
  }
  for (const [name, value] of Object.entries(managedHeaders)) {
    out[name] = value;
  }
  return out;
}

function base64url(bytes) {
  const bin = String.fromCharCode(...bytes);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function generateSecret() {
  return base64url(PLATFORM.crypto.randomBytes(32));
}

function parseMs(raw) {
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

async function loadJsonata() {
  if (jsonataFactory) return jsonataFactory;

  try {
    const mod = await import("jsonata");
    jsonataFactory = mod?.default || mod;
    if (typeof jsonataFactory !== "function") {
      throw new Error("jsonata default export is not a function");
    }
    return jsonataFactory;
  } catch (e) {
    throw new HttpError(
      500,
      "MISSING_JSONATA_DEPENDENCY",
      "jsonata dependency is not available in this Worker build.",
      {
        setup: "Ensure jsonata is listed in package.json dependencies and deploy from repository root.",
        cause: String(e?.message || e),
      }
    );
  }
}

function resolveProxyHostForRequest(config) {
  let configuredTarget = "";
  const configuredRequestUrl = typeof config?.http_requests?.outbound_proxy?.url === "string"
    ? config.http_requests.outbound_proxy.url.trim()
    : "";
  if (configuredRequestUrl) {
    try {
      const u = new URL(configuredRequestUrl);
      configuredTarget = `${u.protocol}//${u.host}`;
    } catch {}
  }
  if (!configuredTarget) {
    throw new HttpError(
      503,
      "MISSING_TARGET_HOST_CONFIG",
      "http_requests.outbound_proxy.url must be configured.",
      {
        hint: "Set http_requests.outbound_proxy.url in config to a valid https URL.",
      }
    );
  }
  return configuredTarget;
}
