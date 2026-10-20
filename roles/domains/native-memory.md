<!-- Adapted from MEMORY-SAFETY-AND-BINARY.md in Cloudflare's security-audit-skill (MIT). See THIRD_PARTY_NOTICES.md. -->
# Native code and memory safety

## Hunt

- Re-derive every bound and lifetime from attacker-controlled input and from all callers. Check the worst accepted case, not a typical one.
- A possible crash is a defect only when realistic untrusted input reaches it. Do not infer memory corruption or code execution from a pattern label alone.
- A check in one caller, architecture, feature flag, or compatibility path does not protect its siblings.

Attack classes:

- **Out-of-bounds read or write**: a length, offset, index, or terminator reaches a buffer without a correct bound. Recalculate headroom after prefixes, alignment, padding, and terminators, and check whether input is read before its declared length is trusted.
- **Integer overflow, truncation, and signedness**: attacker-controlled arithmetic before allocation, copy, loop, index, or pointer math: `a - b` with `b > a`, `count * size`, additions near the type maximum, negative values converted to unsigned, 64-bit lengths narrowed to 32 bits, `-1` sentinels used as sizes.
- **Unit confusion**: bytes versus elements, code units, pages, or wire units mixed between parsing, validation, allocation, and copy. A bound checked in the same wrong unit as the allocation is still wrong.
- **Uninitialized data**: buffers, padding, struct fields, or vector capacity returned, hashed, serialized, or sent across a boundary before initialization.
- **Use-after-free and double free**: owners released while callbacks, timers, iterators, borrowed slices, or cached raw pointers still use them; check every error, cancellation, close, and realloc path.
- **Type confusion**: a tag, vtable, union discriminator, or handle checked differently from how it is later read; unchecked downcasts; tags stale after reuse.
- **Reference-count and ownership races**: non-atomic retain and release, check-then-use without a lock, inconsistent ownership across threads.
- **Shared-state races**: parser streams, global caches, lazy initialization, signal handlers, or teardown invalidating bounds, policy, or pointers established earlier.
- **FFI contract mismatch**: caller and callee disagree on who allocates, frees, or pins a buffer, how long a pointer stays valid, or whether a length is in bytes or elements; null and zero-length handling; Rust `unsafe` blocks that assume invariants the safe API does not enforce.
- **Layout and ABI disagreement**: struct packing, alignment, enum width, callback signature, or calling convention differing between declarations or architectures; panics or exceptions unwinding across an ABI that forbids it.
- **Library and plugin search order**: a privileged process loads a library, plugin, or helper from a path a less trusted user can write, or resolves a bare name through the working directory or environment.
- **Verify-then-load gaps**: a loader checks one file or record but maps another because of path resolution, replacement, or architecture slices.
- **Malformed binary metadata**: offsets, counts, sections, relocations, or bytecode trusted before range and overlap checks.
- **Kernel and privileged interfaces**: user memory read twice (double fetch), unchecked ioctl sizes or table indices, device nodes or admin sockets that validate shape but not caller authority.

Moves:

- For every parser or FFI boundary, tabulate the accepted length and type, the checked representation, the allocation owner, the consumer, the thread, and the teardown; most native findings are one disagreement in that table.
- Diff fixes and duplicated paths for the same source-to-sink shape.

## Verify

- Establish a realistic untrusted entry point and the exact operation that violates a bounds, type, lifetime, ABI, concurrency, loader, or authority invariant, with the worst accepted input that triggers it.
- Name the effect the code shows: invalid read, invalid write, stale alias, wrong object, uninitialized output, unauthorized library load, deadlock, or a safe abort. Do not claim a stronger effect, such as code execution, than the code supports.
- A safely rejected malformed input is not a finding. A user loading their own plugin into their own process is not a boundary violation. A race needs a security-relevant state transition, not only a possible interleaving.
- When reachability depends on build flags, target architecture, allocator behavior, or an opaque foreign library, state which fact outside the repository decides it.
