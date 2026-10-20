<!-- Adapted from CLOUD-AND-DEPLOYMENT.md in Cloudflare's security-audit-skill (MIT). See THIRD_PARTY_NOTICES.md. -->
# Cloud and deployment

## Hunt

- A manifest alone does not prove a live exposure. Establish which environment consumes it, which defaults or overlays change it, and whether that path is active.
- Map each workload identity to the operations and resources it can reach. Broad policy matters only when lower-trust input can drive an unauthorized action.
- Ingress, proxies, service mesh, metadata services, and admission policy are real boundaries, but count a control only when its configuration and attachment are visible.
- A reference to a secret is not disclosure. Look for a lower-trust reader, output, artifact, log, or unsafe fallback.

Attack classes:

- **Workload identity overreach**: a workload, function, or worker identity can act on tenants, accounts, or resources beyond its role, and request or job input selects the target.
- **Cross-account role confusion**: role assumption, external ids, token exchange, or workload federation accepting claims not bound to the intended account, audience, repository, or namespace (for example an OIDC trust policy without a `sub` condition).
- **Authorization delegated to metadata**: the application trusts caller-supplied identity headers, tags, labels, or account ids without proof they came from the control plane or a trusted proxy.
- **Unexpected reachability**: an ingress, service, listener, security group, port mapping, or `0.0.0.0` bind exposes admin, debug, metrics, or internal APIs to a lower-trust network.
- **Proxy and mesh bypass**: a backend accepts forwarded identity from peers outside the intended ingress, or an alternate port or health path skips the mesh; fail-open behavior when the proxy is absent.
- **Metadata service reachability**: an untrusted URL reaches instance or container metadata or control-plane sockets with workload credentials.
- **Host capability exposure**: privileged containers, added capabilities, host namespaces, host paths, runtime sockets, or mounted service-account tokens reachable by lower-trust workloads.
- **Admission inconsistency**: one deployment route enforces image, namespace, or privilege policy and another (job, upgrade, restore) does not.
- **Label and namespace trust**: network, admission, or identity policy keyed on labels or names that a less trusted principal can set.
- **Configuration precedence drift**: development values, chart defaults, environment variables, feature gates, or overlays that disable authentication, TLS, tenant scoping, or audit in a deployed environment.
- **Secret exposure**: secrets in logs, crash reports, process arguments, shared environment, broad volumes, build outputs, or images readable by another workload or tenant.
- **Credential renewal fallback**: failure to mount or refresh a credential leaves a stale one active or switches to a less trusted mode.
- **Object storage and signed URLs**: bucket policies, object keys, or signed URLs that do not bind principal, operation, object prefix, or expiry; public listing or write.
- **Event-source identity**: a function trusts event body fields as the source identity without checking the provider-signed envelope, subscription, or account.

Moves:

- For each maintained environment, list external ports, workload identities, network peers, mounted secrets, and cloud resources; differences need an explanation.
- Follow a lower-trust request, object, label, or event into cloud policy, and name the credential that performs the final operation.

## Verify

- Establish that the configuration is active: which environment uses it and what overlays change it. Name the lower-trust caller or workload, the identity used, the selector they control, the affected resource, and the unauthorized operation or disclosure.
- Missing hardening (no seccomp profile, no read-only filesystem, broad but unreachable policy) is a hardening note unless a reachable operation crosses the boundary.
- Check provider and orchestrator defaults for the pinned versions. Do not assume a public IP, a reachable metadata service, a permissive firewall, or a missing admission policy.
- Account policy, network attachment, runtime admission, and drift between the repository and the live environment are often invisible from source: when one decides the outcome, state which fact it is.
