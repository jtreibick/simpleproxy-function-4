function buildRuntimeRouteHandlers({ proxyRuntimeApi, handleRotateByKind }) {
  return {
    handleRootProxyRequest: (request, env, ctx) => proxyRuntimeApi.handleRootProxyRequest(request, env, ctx),
    handleRequest: (request, env, ctx) => proxyRuntimeApi.handleRequest(request, env, ctx),
    handleRotateByKind,
  };
}

export { buildRuntimeRouteHandlers };
