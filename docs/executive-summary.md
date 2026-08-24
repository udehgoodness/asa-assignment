# Executive Summary: VulnTracker Security Review

## Starting point

This product exists to hold a customer's most sensitive information about their own security weaknesses: every unpatched issue, every system it affects, and how urgently it needs fixing. Before this review, an attacker who simply signed up for a free account (no special access, no insider knowledge required) could have read every other customer's data through several independent paths. One of those paths didn't even require a valid login at all. Login attempts were also being written into system logs in plain text, meaning anyone with routine access to those logs could collect working passwords over time. In short, the product's core promise to keep customer risk data safe was not being kept.

## Current state

The highest-impact issues have been fixed and verified. This wasn't just patching and assuming it works; it was confirmed with automated tests, a real container build, and a real trial deployment to a Kubernetes-like environment. A new feature (shareable, time-limited report links for external stakeholders) was built with security as a starting requirement rather than an afterthought, including protection against repeated password-guessing and a link that can't be silently redirected to an attacker-controlled address. Every fix and every remaining gap is documented with a plain-English reason, not left implicit. The product's status moved from "an interested outsider could plausibly read everyone's data" to "the remaining risks are lower-impact, understood, and have an owner."

## Top 3 residual risks

1. **Some third-party software components are out of date.** Newer, safer versions exist, but several are deeply embedded in how the product handles logins and encryption. Upgrading carelessly risks breaking those in a way that's worse than the problem it fixes. This is scheduled as a deliberate, tested update rather than a rushed one.
2. **The underlying server image carries known weaknesses inherited from its operating system**, not from anything I wrote. This isn't a one-time fix. Like a phone needing regular OS updates, it needs an ongoing refresh process. In the meantime, the container is locked down (no admin rights, no unnecessary permissions) specifically to limit how reachable those weaknesses actually are.
3. **An internal support service has no login of its own.** It currently relies entirely on network isolation (it simply can't be reached from outside) rather than also checking who's asking. That isolation is real and enforced, but a second layer of protection is the more resilient long-term design.

None of these three allow the "read any customer's data" access that existed before this review. They're meaningfully lower stakes, and each has a documented plan.

## Recommended next steps

- **Move off the current file-based database** to a managed database with proper access controls, backups, and the ability to run more than one copy of the service at once.
- **Establish a recurring update cadence** for both application software and the server image. This review fixed a point-in-time list, but security debt regrows without a standing process.
- **Add centralized monitoring for login and data-access activity**, so unusual patterns (e.g. one account reading unusually many records) get flagged automatically instead of relying on a review like this one.
- **Add authentication to internal-only services** as a second layer of defense, rather than relying solely on network isolation.
- **Commission a follow-up test focused specifically on the new sharing feature** and on confirming customer data stays properly separated. This is the highest-value area to re-check as the product evolves.
