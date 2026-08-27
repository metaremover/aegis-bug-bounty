# AegisBugBounty — Autonomous Zero-Day Vulnerability Disclosure & Patch Escrow

> **"An autonomous vulnerability disclosure clearinghouse on GenLayer that evaluates whitehat CVEs, exploit proofs-of-concept, and mitigation git patches to disburse protocol bug bounties via AI consensus."**

---

## 🔗 Verified Deployments & Links
- **GenLayer Explorer Contract**: [`0xee5A0e89Be7587CDf09186F96A04CBAc4cDA4806`](https://explorer-studio.genlayer.com/address/0xee5A0e89Be7587CDf09186F96A04CBAc4cDA4806)
- **GitHub Repository**: [`https://github.com/metaremover/aegis-bug-bounty/`](https://github.com/metaremover/aegis-bug-bounty/)
- **Critical CVE-2026-8891 Advisory Feed**: [`https://metaremover.github.io/aegis-bug-bounty/demo/mock_cve_critical_reentrancy_patch.html`](https://metaremover.github.io/aegis-bug-bounty/demo/mock_cve_critical_reentrancy_patch.html)
- **Medium CVE-2026-8892 Advisory Feed**: [`https://metaremover.github.io/aegis-bug-bounty/demo/mock_cve_medium_oracle_timeout.html`](https://metaremover.github.io/aegis-bug-bounty/demo/mock_cve_medium_oracle_timeout.html)
- **Invalid Spam Advisory Feed**: [`https://metaremover.github.io/aegis-bug-bounty/demo/mock_cve_spam_invalid_report.html`](https://metaremover.github.io/aegis-bug-bounty/demo/mock_cve_spam_invalid_report.html)

---

## 🛡️ Multi-Layer Anti-Replay & Consensus Invariants (Steward Hardened)

1. **Strict CVE Identifier Equivalence Binding**: `cve_identifier` is bound to 100% exact-match validator agreement in the Equivalence Rule criteria. Validators independently audit the advisory DOM and reject any proposal where the CVE identifier contradicts the declared advisory CVE ID.
2. **Payout Safety Invariant Binding**: All fields governing replay protection and payout eligibility (`cve_identifier`, `security_verdict`, `cvss_score_x10`, `advisory_valid`, `clock_fresh`) are strictly bound to independent validator agreement before state mutation.
3. **`[ERR_REPLAY_01]` Report ID Uniqueness**: Blocks duplicate `report_id` submissions.
4. **`[ERR_REPLAY_02]` Program-Bound CVE Uniqueness**: Prevents re-submitting the same CVE identifier under different report IDs to double-claim bounties (`disbursed_cves`).
5. **`[ERR_REPLAY_03]` Advisory Feed URL Uniqueness**: Prevents re-submitting the same disclosure feed URL to repeatedly debit the protocol bounty pool (`disbursed_advisories`).
6. **`[ERR_REPLAY_04]` Exploit Digest Uniqueness**: Binds CVE vulnerability metrics to prevent identical disclosures under altered URLs.
7. **Deterministic Solvency Tracking**: Automatically deducts approved bounties from the program pool (`paid_bounties_usdc`) and freezes depleted pools (`DEPLETED_FROZEN`).
