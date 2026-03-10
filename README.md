# simpleproxy-function

Generated from core repo commit 5c99bb14ac327a66c7ca8faeed249129d8c6afe6.

Entrypoint: src/runtime/runtime_entry.js
Deploy: wrangler deploy

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/codenada/simpleproxy-function)

Default: Cloudflare one-click deploy (button above).
Platform adapter default is Cloudflare via `src/platform/index.js`.

You can replace adapter wiring and use any deployment pipeline in your own repo.

Cloudflare Import-Repo settings (recommended default):
- Build command: (leave blank)
- Deploy command: wrangler deploy
- Root directory: /
