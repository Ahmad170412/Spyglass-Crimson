# Ethics & Acceptable Use

**Spyglass-Crimson is a passive open-source intelligence (OSINT) tool. It resolves and
correlates *publicly available* data about domains, IP addresses, and autonomous systems.
That is the entire scope of what it does, and that scope is a hard boundary — not a default
setting you are free to change.**

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

The aggressive-scanning gate in this application exists to make you record that
authorization. It is not a formality, and bypassing it is a violation of this policy.

## 2. Passive means passive

This tool queries third-party public services (RDAP, DNS resolvers, certificate
transparency logs, and similar). It does not, and must not, send traffic to the target
itself.

- Do **not** extend it to port-scan, brute-force, fuzz, exploit, or otherwise touch a
  target's systems.
- Do **not** use it to enumerate vulnerabilities for the purpose of exploitation.
- Do **not** wrap it in automation that hammers upstream providers. Respect rate limits
  and each provider's terms of service.

If you add an active module, you are on your own, and you assume full responsibility for
what it does. The maintainers will not support, endorse, or defend active scanning.

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
code whose primary purpose is to evade the boundaries above (for example: active scanning
payloads, credential-stuffing integrations, or doxxing helpers). Maintainers may reject or
revert any contribution that weakens these guarantees.

---

**TL;DR:** Run it against your own infrastructure, or against targets you are explicitly
authorized to assess. Keep it passive. Respect people's privacy. Don't be the reason this
tool gets abused — you will answer for that, not us.
