function readRuntimeEnv(env) {
  return {
    allowedHosts: String(env?.ALLOWED_HOSTS || "").trim(),
    buildVersion: String(env?.BUILD_VERSION || "dev"),
    buildTimestamp: String(env?.BUILD_TIMESTAMP || env?.BUILD_TIME || ""),
  };
}

function loadRuntimeAdminConfig() {
  return {
    admin: {
      get_admin_token_endpoint: { enabled: false, rpm_rate_limit: 10 },
    },
  };
}

const RUNTIME_RESERVED_ROOT = "/_apiproxy";
const RUNTIME_REQUEST_PATH = `${RUNTIME_RESERVED_ROOT}/request`;
const RUNTIME_PROXY_ROTATE_PATH = `${RUNTIME_RESERVED_ROOT}/keys/proxy/rotate`;
const RUNTIME_ISSUER_ROTATE_PATH = `${RUNTIME_RESERVED_ROOT}/keys/issuer/rotate`;

export {
  readRuntimeEnv,
  loadRuntimeAdminConfig,
  RUNTIME_RESERVED_ROOT,
  RUNTIME_REQUEST_PATH,
  RUNTIME_PROXY_ROTATE_PATH,
  RUNTIME_ISSUER_ROTATE_PATH,
};
