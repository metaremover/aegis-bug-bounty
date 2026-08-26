# AegisBugBounty — Autonomous Zero-Day Vulnerability Disclosure & Patch Escrow

> **"An autonomous vulnerability disclosure clearinghouse on GenLayer that evaluates whitehat CVEs, exploit proofs-of-concept, and mitigation git patches to disburse protocol bug bounties via AI consensus."**

---

## 🔗 Verified Deployments & Links
- **GenLayer Explorer Contract**: [`0x394DF5239403d359C267B6B1F665d8847f5818cc`](https://explorer-studio.genlayer.com/address/0x394DF5239403d359C267B6B1F665d8847f5818cc)
- **GitHub Repository**: [`https://github.com/metaremover/aegis-bug-bounty/`](https://github.com/metaremover/aegis-bug-bounty/)
- **Critical CVE-2026-8891 Advisory Feed**: [`https://metaremover.github.io/aegis-bug-bounty/demo/mock_cve_critical_reentrancy_patch.html`](https://metaremover.github.io/aegis-bug-bounty/demo/mock_cve_critical_reentrancy_patch.html)
- **Medium CVE-2026-8892 Advisory Feed**: [`https://metaremover.github.io/aegis-bug-bounty/demo/mock_cve_medium_oracle_timeout.html`](https://metaremover.github.io/aegis-bug-bounty/demo/mock_cve_medium_oracle_timeout.html)
- **Invalid Spam Advisory Feed**: [`https://metaremover.github.io/aegis-bug-bounty/demo/mock_cve_spam_invalid_report.html`](https://metaremover.github.io/aegis-bug-bounty/demo/mock_cve_spam_invalid_report.html)

---

## 🛡️ Multi-Layer Anti-Replay Invariants (Joaquin Review Hardened)

1. **`[ERR_REPLAY_01]` Report ID Uniqueness**: Blocks duplicate `report_id` submissions.
2. **`[ERR_REPLAY_02]` Program-Bound CVE Uniqueness**: Prevents re-submitting the same CVE identifier (e.g. `CVE-2026-8891`) under different report IDs to double-claim bounties (`disbursed_cves`).
3. **`[ERR_REPLAY_03]` Advisory Feed URL Uniqueness**: Prevents re-submitting the same disclosure feed URL to repeatedly debit the protocol bounty pool (`disbursed_advisories`). Revert verified on-chain.
4. **`[ERR_REPLAY_04]` Exploit Digest Uniqueness**: Binds CVE vulnerability metrics to prevent identical disclosures under altered URLs.
5. **Deterministic Solvency Tracking**: Automatically deducts approved bounties from the program pool (`paid_bounties_usdc`) and freezes depleted pools (`DEPLETED_FROZEN`).
