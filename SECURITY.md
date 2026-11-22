# Security model

This is an unaudited prototype for synthetic local experiments, not a production secret store.

## Trusted components

The broker, its operator, the owner's connector, and the human approval surface are trusted.
The peer agent, peer-provided fields, and source message contents are not authority.
The broker is not permitted to call Gmail or a financial service: it has no such credentials
or tool. Only the owner-controlled connector can implement source access.

An agent credential proves possession of an enrolled secret, not a legal identity, relationship,
or physical human presence. Setup's `owner_a`/`owner_b` identities are fictional. Verify the
person separately before distributing a profile. SHA-256 hashes of random 256-bit bearer
secrets are stored by the server; profiles contain the actual secrets. Rotation requires
replacing the credential hash/profile and restarting the broker. Never reuse human tokens
as agent tokens. Do not commit either profile or server configuration.

The demo's common `.state/profiles` directory is a convenience, not a security boundary.
An agent with filesystem access to that directory can steal the human credential. For real
use, human approval must run on a separate device/account or authenticated service that the
agent cannot access. A TTY prompt is a review affordance, not proof that a human approved.

## Authorization and disclosure

Only mutually enrolled peers can request. The authenticated caller, never the body, supplies
the requester identity. Commands accept only fixed fields and enumerated operation types.
No peer-provided prompts, callback URLs, shell strings, recipient overrides, or Gmail queries
are accepted. There is no dynamic tool selection or credential passthrough.

The command digest binds request ID, owner, recipient, canonical command, and expiration.
Read approval is allowed only with that owner's human credential. A transaction changes
`read_approved` to `preparing` exactly once. The connector must claim BEFORE source access.
The broker cannot police source calls made independently by an agent that already has Gmail
credentials. To enforce that boundary, give Gmail credentials only to a constrained local
gateway that accepts broker-authorized claims; do not give them to the general agent.

The prepared response is immutable. A second digest binds it to the original command digest.
Only the owner human can approve this digest. The requester cannot see a candidate or its
digest before release. Reusing an approval for another request or changing the candidate is
rejected. SQLite write transactions serialize competing claims, approvals, and revocations.

Approvals are one-time state transitions; retrieval of an already approved result can be
repeated until expiry or revocation. There is no automatic approval, delegated human role,
or reusable session grant. The initial relationship enrollment does not grant source access.

## Data minimization

Flights match departure day in the request's IANA timezone. A hotel matches an overlapping
stay: check-in inclusive, check-out exclusive; hotel dates are hotel-local calendar dates.
Card reminders match the due date. This distinction is fixed, not inferred from a prompt.
Only requested fields are released. Duplicate projected records are collapsed. Missing
required filter data, invalid dates, or invalid requested values cause preparation to fail.

The supplied connector projects locally before upload. Raw emails, names, booking codes,
card numbers, balances, addresses, and attachments have no output fields. The broker also
projects, so extra input keys are dropped and never persisted. Do not send raw source
records to the broker in a real adapter: discarded data still traverses the broker process.

Free text, even in a hotel-name field, can contain personal information or covert data.
The regex check blocks some obvious emails, long digit strings, URLs, and control characters;
it is neither comprehensive DLP nor a proof of relevance or authenticity. Inspect the exact
preview and reject questionable output. Structured allowlists reduce risk; they do not make
LLM extraction trustworthy. Source text must be treated as data, never tool instructions.
The v0 ASCII text policy is deliberately narrow and does not support all international names.

## Transport, availability, retention

The CLI serves loopback only, without access logs. Bearer credentials are sent in headers.
The SDK refuses non-loopback plain HTTP and redirects, and ignores environment proxies.
There is no CORS or cookie authentication. A hosted deployment requires a TLS termination
layer, ingress limits, hardened identity management, and a trusted broker operator. This v0
does not include public hosting or Internet-scale DoS protection.

Requests are limited to 30 per hour and 10 active per requester. Bodies are limited to 64 KiB;
candidates to 50 records. Events contain only IDs, type, and timestamp. One local listener
per agent is supported. Delivery is at least once; handlers must be idempotent. The connector
claim is at most once. A crash after a claim fails closed; request again instead of silently
repeating a source read. An already-running source call cannot be recalled by revocation,
but its result cannot be prepared/released after revocation. Configure bounded source calls.

TTL defaults to 30 minutes, maximum 60. Access checks enforce expiry; a 30-second janitor
also clears expired payloads while the server runs. Closed request metadata/events are deleted
24 hours after expiry; action-only audit rows expire after seven days. The owner audit API
joins surviving requests, so it exposes at most the surviving request retention window.
No cleanup occurs while the server is stopped; startup resumes it. File deletion is not
guaranteed physical erasure on SSDs, backups, or snapshots. Disk encryption is your responsibility.
Revocation cannot erase responses already copied by recipients.

## Repository privacy

Only code, synthetic fixtures, and documentation belong in Git. `.state/`, `.env*`, database
files, private keys, logs, and `local/` are ignored. The repository guard checks tracked files
for sensitive paths, token/private-key patterns, and non-synthetic email addresses. Git history
also carries author metadata; the initial project commit uses an anonymous placeholder.
The guard is not a general PII detector. Inspect staged diffs before publishing.

Report security problems privately to the repository owner. Do not include live tokens,
real itineraries, emails, or card data in an issue.
