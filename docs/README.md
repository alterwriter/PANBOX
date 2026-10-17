# PANBOX documentation

This public documentation describes the current alpha implementation and its limits. For a quick overview, start with the [project README](../README.md).

| Need | Document |
|---|---|
| Install the dashboard and agent, then operate PANBOX | [English product and operator guide](product-guide-en.md) or [Panduan produk dan operator Bahasa Indonesia](product-guide-id.md) |
| Understand the runner, API, database, and private network routes | [Architecture](architecture.md) |
| Get started in Bahasa Indonesia | [Quickstart](quickstart-id.md) |
| Build an integration against supported endpoints | [OpenAPI contract](../api/openapi.yaml) |
| Review supported release assets and current limits | [Release notes](release-notes.md) |

The native agent source is under [`cmd/panbox`](../cmd/panbox) and [`internal/scanner`](../internal/scanner). The server source is under [`cmd/panbox-server`](../cmd/panbox-server) and [`internal/server`](../internal/server). Keep scan keys in a secret manager and use a protected runner for CI.
