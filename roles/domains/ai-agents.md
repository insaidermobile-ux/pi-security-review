<!-- Adapted from AI-AND-LLM.md in Cloudflare's security-audit-skill (MIT). See THIRD_PARTY_NOTICES.md. -->
# AI, LLM, and agents

## Hunt

- Prompt injection alone is not a finding. Look for a code-level boundary failure: untrusted content reaches another principal's model context, invokes authority the requester lacks, discloses data they cannot read, or drives a sink they cannot reach directly.
- Model output, memory, tool descriptions, and MCP responses are untrusted input. A guardrail prompt is not a security boundary; only deterministic checks, resource-scoped authorization, isolation, and constrained credentials count.
- The key data flow is untrusted content → model or memory → capability, authority, or sink.

Attack classes:

- **Indirect injection through retrieved content**: an attacker writes a document, page, file, email, issue, or tool response that enters a different principal's context. Trace who can write each source, how retrieval scopes it, whose session consumes it, and what capability is enabled there.
- **Cross-session or cross-tenant context bleed**: history, embeddings, retrieval results, or prompt caches keyed too broadly. Check tenant and ACL filters in the query itself and in every cache key.
- **Persistent memory poisoning**: attacker content or model summaries written to memory that later shapes another user's or a privileged task. Check who may create, update, and merge memory, and whether low-trust observations become durable instructions.
- **Role and provenance confusion**: prompt assembly lets untrusted text pose as a system message, earlier turn, tool result, or policy, through string concatenation, caller-controlled role fields, or serialization that drops source labels.
- **Tool-argument injection**: model-produced arguments reach SQL, shell, file, URL fetch, or privileged APIs without validation in the handler. A tool schema narrows shape; it does not establish authorization, safe paths, or safe URLs.
- **Excessive agency and confused deputy**: the agent acts with a service identity or broad credential, and the tool handler does not re-check the requesting principal's permission on the named resource.
- **Approval binding**: a user approves one action but execution can use changed arguments, another resource, another principal, or a later turn; or attacker content triggers a side effect under a victim's authority that the victim never requested. Check retries and resumed sessions.
- **Schema and dispatcher disagreement**: aliases, extra fields, duplicate keys, coercions, or defaults that the validator and the handler interpret differently.
- **Unbounded delegated loops**: one request can enqueue repeated spend, sends, or mutations without a per-request budget, per-action authorization, or idempotency.
- **Sub-agent and MCP trust inheritance**: delegated tasks receive the full session, credentials, or memory instead of the least authority needed; delegated results are trusted on return.
- **MCP identity confusion**: calls or results routed by server names, tool names, request ids, or resource URIs an attacker can influence, rather than by the authenticated connection and outstanding request.
- **MCP metadata as policy**: tool descriptions, schemas, or hints from an MCP peer treated as authorization.
- **Insecure output rendering**: model output reaches HTML, Markdown, template, URL, or command sinks without the encoding the sink needs.
- **Sensitive context extraction**: the assembled context holds credentials or another user's data, and user-influenced output can expose them.

Moves:

- Map execution identities, capabilities, writable context or memory sources, and output destinations, then connect the principal at the start to the authority at the end.
- Start at side-effecting tools and work back through dispatcher, schema, confirmation, context, retrieval, and ingestion. Start at memory reads and trace every writer.
- Compare direct, queued, retry, resume, batch, and delegated paths for the same action.

## Verify

- Prompt injection alone is not a finding. Name the crossed boundary: attacker, affected principal or shared resource, execution identity, target, and the unauthorized or unrequested action or disclosure.
- For confused-deputy claims, show that the tool lacks requester-and-resource authorization and that the attacker cannot perform the same action through the normal interface. For approval-binding claims, show that attacker content caused an action under the victim's authority that the victim did not request or approve; generic authorization does not establish intent.
- For memory or retrieval claims, cite both the attacker-controlled write and the later cross-principal read or privileged decision. A shared record with no reachable consumer is not enough.
- Disclosure of generic instructions or system prompts that cross no data boundary is not a finding. An intentional request that uses the requester's own authority is not a delegation defect because a model executes it.
- When the outcome depends on model provider behavior, an external MCP server's identity, or a renderer outside the repository, state which fact outside the repository decides it.
