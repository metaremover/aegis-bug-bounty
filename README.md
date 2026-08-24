# AegisBugBounty — Autonomous Zero-Day Vulnerability Disclosure & Patch Escrow

> **"A decentralized, trustless vulnerability disclosure clearinghouse for Web3 protocols and whitehat security researchers powered by GenLayer AI consensus."**

---

## 🔗 Verified Deployments & Links
- **GenLayer Explorer Contract**: [`0x06b91b8474CC8129cE7B2A23f658C1dB5e0f9A7B`](https://explorer-studio.genlayer.com/address/0x06b91b8474CC8129cE7B2A23f658C1dB5e0f9A7B)
- **GitHub Repository**: [`https://github.com/metaremover/aegis-bug-bounty`](https://github.com/metaremover/aegis-bug-bounty)

---

## 🛡️ Multi-Layer Anti-Replay Architecture (Joaquin Review Compliant)

1. **Unique Report ID Assertion**:
   - `assert r_id not in self.bounty_reports` (`[ERR_REPLAY_01]`).
2. **Program-Bound CVE Uniqueness Guard**:
   - `disbursed_cves` mapping prevents re-submitting the same CVE under a different report ID to double-claim a bounty (`[ERR_REPLAY_02]`).
3. **Advisory Feed Uniqueness Binding**:
   - `disbursed_advisories` mapping prevents re-submitting the same advisory URL to repeatedly debit the protocol bounty pool (`[ERR_REPLAY_03]`).
4. **Access Control & Program Telemetry Whitelisting**:
   - Restricts triage submission to authorized operators, program sponsors, and whitehat claimants.
5. **Unified Single-Round Consensus**:
   - 24/7 UTC Atomic Clock (`timeapi.io`) and CVSS advisory DOM evaluated in 1 parallel prompt pass.
