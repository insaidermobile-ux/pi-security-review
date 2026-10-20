<!-- Adapted from PROTOCOLS-RPC-AND-MESSAGING.md in Cloudflare's security-audit-skill (MIT). See THIRD_PARTY_NOTICES.md. -->
# RPC and messaging

## Hunt

- "Internal" is not authentication. Name the peer identity at every hop and show how it becomes the application principal used for authorization.
- Schema validation proves message shape, not provenance, resource authority, ordering, or safe values. Follow decoded fields to policy and side effects.
- Broker guarantees and application guarantees differ. Note retry, ordering, acknowledgement, deduplication, and transaction behavior before judging state changes.

Attack classes:

- **Boundary and canonicalization disagreement**: components disagree on length, compression, duplicate or unknown fields, encoding, numeric width, or envelope-versus-body precedence, so the principal, resource, or operation differs after decoding.
- **Union, enum, and default confusion**: unknown variants, missing discriminators, zero values, or default privileges reach code that assumes a validated case; old consumers misread new fields.
- **Envelope and payload mismatch**: authorization uses routing or envelope metadata while the handler acts on a different tenant, subject, or object named in the body.
- **Interceptor gaps**: an authentication or authorization interceptor covers unary calls but not streams, reflection, health, gateway-transcoded routes, compatibility services, or individual stream messages.
- **Peer identity versus claimed principal**: mTLS, workload identity, or broker credentials authenticate the channel, but a caller-controlled field selects the user or tenant.
- **Per-item and streaming authorization**: a stream, subscription, or batch is authorized once, then later items name other resources or continue after revocation.
- **Reply correlation confusion**: predictable or reused correlation ids let a response, webhook, cancellation, or acknowledgement satisfy another caller's pending operation.
- **Topic and subscription scope**: a publisher or subscriber can choose another tenant's topic, wildcard, consumer group, reply queue, or dead-letter route. Tenant text inside a payload is not isolation.
- **Failure-path disclosure**: dead-letter queues, error topics, traces, or operator views carry secrets or cross-tenant payloads to a lower-trust reader.
- **Untrusted producer as control plane**: a message declares itself an admin event, provider callback, or migration instruction without an authenticated producer; webhooks without signature verification or with a non-constant-time comparison.
- **Duplicate delivery**: retries repeat a side effect because deduplication is missing, runs after the mutation, or uses a key that collides across tenants.
- **Stale and out-of-order messages**: older state, revoked membership, or cancelled work arrives late and overwrites newer state.
- **Acknowledge and commit ordering**: acknowledgement before durable commit loses security-relevant work, or commit before acknowledgement duplicates a mutation.
- **Partial multi-consumer transitions**: several consumers implement one authorization or business transition and partial failure leaves only some of it applied.

Moves:

- For each message family, draw producer → transport → gateway → consumer → storage, and record at each hop the authenticated peer, the authoritative tenant and resource fields, the validation, and the side effect.
- Compare normal, retry, dead-letter, replay, stream, reflection, and gateway routes for the same operation.

## Verify

- Name the realistic producer or peer, the accepted message, the authenticated channel identity, the affected principal or resource, and the unauthorized mutation or disclosure.
- For parser disagreement, cite both parsers or consumers and the value they decode differently. If either side rejects the message safely, the claim fails.
- For replay and ordering claims, establish the actual delivery guarantees from code and configuration before claiming an invariant failure.
- Check every interceptor, gateway, and consumer layer visible in the repository. Broker ACLs, mesh identity, and topic attachments are often configured elsewhere: when one decides the outcome, state which fact it is.
