# AegisBugBounty — Autonomous Zero-Day Vulnerability Disclosure & Patch Escrow

> **"A decentralized vulnerability disclosure clearinghouse on GenLayer that audits whitehat CVE advisories and git patches to autonomously disburse bug bounties without human friction or protocol counterparty risk."**

---

## 🌟 The Core Problem

Web3 bug bounty platforms (Immunefi, HackerOne) suffer from trust dilemmas:
1. **Whitehat Vulnerability Fear**: Researchers hesitate to disclose multi-million dollar zero-day bugs fearing protocols will patch the bug without paying or lowball the severity.
2. **Protocol Spam & Extortion**: Protocols are flooded with AI-generated false positive reports.

**AegisBugBounty introduces autonomous on-chain vulnerability triage**:
1. **Program-Bound Escrow Vault**: Protocols lock USDC bounty funds with deterministic tier limits.
2. **Semantic CVE & Git Patch Audit**: AI validators cross-examine exploit proof-of-concepts, CVSS v3.1 attack vectors, and mitigation git diffs via `gl.nondet.web.render()`.
3. **Autonomous Escrow Release**: Valid critical exploits trigger automatic bounty release to the whitehat's wallet without centralized intermediary delays.

---

## 🛡️ Key Architectural Invariants

- **Caller Access Control**: Audit execution restricted to authorized triage operators, protocol sponsors, and researcher claimants.
- **Program-Bound Telemetry Whitelist**: Enforces that CVE advisories must be bound to the registered bounty covenant.
- **Anti-Replay Unique Audit IDs**: Reused report IDs are strictly rejected on-chain (`assert r_id not in self.bounty_reports`).
- **Single-Round Unified Consensus**: Combines 24/7 UTC Atomic Clock (`timeapi.io`) and vulnerability advisory DOM in **1 parallel prompt** (0 leader rotations).
- **100% Fail-Closed Resilience**: Unparseable reports or forged DOMs fail closed, safeguarding protocol treasury capital.

---

## 📖 Test Cases & Verification Matrix

| Test ID | CVE Identifier | CVSS | Exploit Class | Expected Verdict | On-Chain Action |
|---|---|---|---|---|---|
| **TC-01** | `CVE-2026-8891` | 9.8 (Critical) | Reentrancy Pool Drain | `CRITICAL_EXPLOIT_VERIFIED` | **$100,000 USDC Bounty Awarded** |
| **TC-02** | `CVE-2026-8892` | 6.5 (Medium) | Oracle Heartbeat Staleness | `MEDIUM_SEVERITY_APPROVED` | **$25,000 USDC Bounty Awarded** |
| **TC-03** | `INVALID-SPAM-001` | 0.0 (None) | Informational / Out-of-scope | `INVALID_REJECTED` | **$0 Disbursed (Report Rejected)** |
| **TC-04** | `TC-01 Replay` | — | Duplicate Submission | Reverts on-chain | `[ERR_REPLAY_01] Duplicate Rejected` |
