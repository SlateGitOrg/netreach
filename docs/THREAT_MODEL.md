# Threat model

netreach is a **defensive, offline** analysis tool. It reads a JSON snapshot
of VPC configuration that the operator already has, and reports which flows
the configuration admits. It never contacts a cloud API, never sends a
packet, and never needs credentials.

## What it helps defend against

The adversary in scope is an **internet (or lateral, in-VPC) attacker
looking for reachable services** created by configuration mistakes:

| Mistake | How netreach surfaces it |
|---|---|
| A management or database port open to `0.0.0.0/0` | `analyze` grades it `high`; `-fail-on high` makes it a CI gate |
| A rule that looks closed but is overridden by a broader one (SG union) | exposure rows name the admitting rule |
| A NACL deny that is shadowed, or an allow that never takes effect | `validate` lint: shadowed entries, redundant SG rules |
| An instance thought private but reachable (public IP + IGW route) | per-ENI exposure with the full path |
| Reachability across peerings that was meant to be blocked (and the reverse) | internal-ingress query with route/peering hops |
| Egress that silently fails or partly works (stateless NACL replies, NAT port range) | egress query; `why` lists denied NAT ports |

## Trust assumptions

* **The snapshot is accurate.** netreach answers questions about the model,
  not about the live network. A stale or incomplete export (missing NACL
  entries, missing secondary CIDRs, unexported load balancers) produces
  wrong answers. Unknown JSON fields are rejected so typos do not silently
  drop rules, and every reference is validated.
* **The modelled semantics match AWS for the supported features**
  (see DECISIONS.md). Unsupported features are rejected at validation where
  possible (for example middlebox routes) rather than guessed at. Features
  that are simply absent from the schema (load balancers, transit gateways,
  VPN, endpoints, IPv6) are invisible: their absence is a false negative for
  exposure, which is the dangerous direction. The README's Limitations
  section lists them.
* **Under-approximation vs over-approximation.** Within the supported model
  the analysis is exact (no sampling). Two deliberate conservative choices
  exist: a NAT path is reported blocked unless replies are admitted for every
  possible NAT port, and asymmetric return routes are reported blocked.
  Neither hides exposure; both can hide connectivity that works some of the
  time.

## The tool's own attack surface

* **Input**: snapshot files are parsed with `encoding/json` in strict mode.
  There is no code execution, templating or network access driven by input.
* **Resource use**: the header-space representation has polynomial
  worst-case growth in the number of rules (docs/ARCHITECTURE.md). A
  deliberately adversarial snapshot with many crafted overlapping rules could
  make an analysis slow or memory hungry. No limits are enforced; run it on
  exports you trust, and treat the benchmark numbers as typical, not
  worst-case.
* **Output**: reports contain network topology details (addresses, rule
  sets, which ports are open). Treat them with the same sensitivity as the
  snapshot itself; do not publish them.

## Out of scope

* Live scanning, packet injection, or any interaction with real systems.
* Host-level controls (OS firewalls, listening sockets): a "reachable" port
  is reachable at the network layer; whether anything listens is unknown.
* Identity, IAM, and application-layer authorization.

## Ethical use

All fixtures are synthetic. Addresses use RFC 5737 documentation ranges
where they stand for arbitrary internet hosts; example public IPs inside the
fixtures are placeholders and are never contacted. Use netreach on
configurations you own or are authorized to review.
