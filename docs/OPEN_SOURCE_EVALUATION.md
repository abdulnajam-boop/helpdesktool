# External open-source evaluation

Reviewed for architectural fit on 2026-08-16. The execution environment could not
reach GitHub, so licenses and current terms **must be revalidated from each upstream
repository before adoption or redistribution**. No upstream source or dependency was
copied into Helpdesk by this change.

| Project | Decision | Helpdesk role | Dependency / license posture |
| --- | --- | --- | --- |
| [n8n](https://github.com/n8n-io/n8n) | **Integrate externally** | Consume signed generic Helpdesk webhooks for Slack, Teams, email, Jira, ServiceNow and reporting. | Do not embed or make it a security authority. Its source-available/fair-code terms require review for hosted/embedded commercial use. |
| [Open WebUI](https://github.com/open-webui/open-webui) | **Reference; possibly integrate separately later** | Provider configuration, OpenAI-compatible endpoints, Ollama, RAG, MCP and tool UX patterns. | Do not copy code or replace the product UI. Revalidate its current license and branding terms before reuse. |
| [public-apis](https://github.com/public-apis/public-apis) | **Research only** | Discover candidate threat-intelligence, reputation, notification, cloud and enrichment APIs. | Never a runtime dependency. Review every selected API's terms, privacy, auth, rate limits and reliability separately. |
| [Awesome Selfhosted](https://github.com/awesome-selfhosted/awesome-selfhosted) | **Research only** | Discover SSO, monitoring, logging, knowledge, status and notification products for build-versus-integrate decisions. | Catalog content is not a production component; verify each listed project's maintenance and license independently. |
| [Vaultwarden](https://github.com/dani-garcia/vaultwarden) | **Separate operator tool; avoid coupling** | Optional human password management, not endpoint secret distribution. | Upstream is AGPL-3.0. Do not copy its code into Helpdesk without accepting/documenting the resulting obligations. Build a generic `SecretsProvider` for cloud vaults instead. |
| [Excalidraw](https://github.com/excalidraw/excalidraw) | **Defer** | Future incident topology, root-cause and troubleshooting diagrams through an isolated export/embed boundary. | No MVP dependency. Revalidate its license and embedding/security model when prioritized. |
| [video-shotcraft](https://github.com/Vincentwei1021/video-shotcraft) | **Developer/marketing tooling only** | Product demos and release media, potentially installed as a Codex skill. | Never production runtime. License could not be verified in this environment; do not install or copy until reviewed. |

## Component strategy

- **Build:** tenant/security policy, incident state, remediation registry, audit ledger,
  agent protocol, approval, rollback, event contracts and integration authorization.
- **Integrate:** OIDC identity providers, n8n workflows, cloud secret managers, ticketing,
  messaging and observability products through narrow adapters.
- **Avoid:** embedding workflow engines in the security path, unrestricted credential
  access from endpoints, AGPL source mixing without an explicit business decision, and
  runtime dependencies used only for marketing or discovery.
