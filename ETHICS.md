# Ethics & Acceptable Use

**Spyglass-Crimson is a passive open-source intelligence (OSINT) tool. It resolves and
correlates *publicly available* data about domains, IP addresses, and autonomous systems.
It also ships three optional active modules — an HTTPS probe, a bounded TCP port scan, and
curated vulnerability-template checks — and those modules only run against a target you
have recorded an authorization for. Everything else is passive. That boundary is enforced
in code, and it is enforced on purpose.**

Read this before you run it. Using this software means you accept these terms. If you do
not accept them, do not use this software, and do not contribute to it.

## 1. Authorization is not optional

You may only run this tool against infrastructure **you own** or have **explicit, written,
documented authorization** to assess.

- "It's on the public internet" is not authorization.
- "Nobody will notice" is not authorization.
- "I'm just curious" is not authorization.
- A bug bounty program's scope defines authorization; anything outside that scope does not.
- Being an employee is not authorization unless your role explicitly includes it.

The authorization gate in this application exists to make you record that authorization
before any active module can run. It is not a formality, and bypassing it is a violation
of this policy. A recorded authorization is a claim *you* make; it is not a permission
slip issued by the maintainers, and it does not make an unlawful scan lawful.

## 2. Passive by default, active only when authorized

By default this tool queries third-party public services (RDAP, DNS resolvers, certificate
transparency logs, and similar). It does not send traffic to the target.

The active modules are opt-in per run:

- **HTTP probe** — one HTTPS `GET` to the target's root path, no redirects, at most 64 KiB
  of the response body.
- **Port scan** — `nmap` TCP connect scan of the **top 100 ports** on **one host**, with no
  OS detection, no NSE scripts, no UDP, and a 30-second host timeout. It does not sweep
  CIDR ranges or ASNs.
- **Template checks** — `nuclei` with a curated, detection-oriented tag set, excluding
  `dos`, `fuzz`, `intrusive`, `brute-force`, and `default-login` templates, capped at 20
  requests per second, 30 seconds, and 50 findings, with out-of-band interaction disabled.

Every active module:

- refuses to run unless a recorded, unexpired authorization exists for that exact target,
  checked server-side at plan time, again at execution time, and again inside the module;
- refuses to connect to any address that is not globally routable — loopback, RFC 1918,
  CGNAT, link-local, and reserved space — so it cannot be turned into an SSRF gadget
  against your own machine or network;
- accepts a single host only. CIDR and ASN targets never receive active traffic.

Port scanning and vulnerability-template checks can disrupt fragile services, trigger
intrusion detection, or violate a provider's terms of service. **You run them entirely at
your own risk.** The maintainers do not sanction any particular target, do not verify your
authorization, and accept no responsibility for the consequences.

- Do **not** use this tool to enumerate vulnerabilities for the purpose of exploitation.
- Do **not** raise the rate, port count, timeout, or template scope to turn a bounded check
  into a sweep, and do not remove the `-no-interactsh` or exclusion guardrails.
- Do **not** wrap it in automation that hammers upstream providers or the target. Respect
  rate limits and each provider's terms of service.

If you add a further active module, it must be gated on a recorded authorization, refuse
non-public address space, operate on one host, and enforce a documented time/rate/scope
bound. You assume full responsibility for what it does. The maintainers will not support
or defend unbounded active scanning.

## 3. Data handling

Results may contain personal data (registrant details, contact records, correlated
hostnames). You must:

- Process only what you have a lawful basis to process under applicable law
  (GDPR, CCPA, and equivalents).
- Not dox, stalk, harass, or profile individuals.
- Not retain data longer than your stated purpose requires.
- Not share results in a way that exposes private individuals to harm.

You are the data controller. This tool makes you an operator of sensitive lookups; it does
not make those lookups lawful on your behalf.

## 4. What is prohibited

Using Spyglass-Crimson to:

- Reconnaissance for unauthorized intrusion, fraud, abuse, or any illegal purpose.
- Circumvent access controls, authentication, or rate limits on any service.
- Collect data about individuals for harassment, discrimination, or retaliation.
- Violate any applicable law, regulation, or third-party terms of service.
- Build or feed a surveillance product targeting people without consent or legal basis.

## 5. No warranty, no liability cover

This software is provided "AS IS" under the MIT License. The authors and contributors are
**not liable** for how you use it. Misuse is your responsibility, alone. "I used an open
source tool" is not a legal defense, and the license does not shield you from the
consequences of unlawful use.

## 6. Reporting misuse

If you become aware of this tool being used to harm people or systems, report it to the
maintainers via a GitHub Security Advisory. Good-faith reports are welcomed and protected.

## 7. Contributors

By contributing you affirm that your contributions are lawful and that you will not submit
code whose primary purpose is to evade the boundaries above — for example, additional
active modules that bypass authorization, unbounded scanners, credential-stuffing
integrations, or doxxing helpers. Maintainers may reject or revert any contribution that
weakens these guarantees.

---

**TL;DR:** Run it against your own infrastructure, or against targets you are explicitly
authorized to assess. Stay passive unless you have recorded authorization — then the three
bounded active modules are available to you at your own risk. Respect people's privacy.
Don't be the reason this tool gets abused — you will answer for that, not us.
