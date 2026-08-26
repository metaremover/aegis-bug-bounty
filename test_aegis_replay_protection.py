#!/usr/bin/env python3
"""
AegisBugBounty Multi-Layer Replay Protection Test Suite
======================================================
Validates all anti-replay invariants requested by Joaquin:
1. Report ID Uniqueness ([ERR_REPLAY_01]).
2. Program-Bound CVE Uniqueness ([ERR_REPLAY_02] - blocks double-claiming same CVE under different report ID).
3. Advisory Feed Uniqueness ([ERR_REPLAY_03] - blocks re-submitting same advisory feed).
4. Bounty Vault Accounting & Solvency Tracking.
"""

import sys
import logging
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')


class MockAegisBugBounty:
    def __init__(self, operator: str):
        self.operator = operator.lower()
        self.programs: Dict[str, Dict[str, Any]] = {
            "PROG_AEGIS_LENDING_01": {
                "program_id": "PROG_AEGIS_LENDING_01",
                "protocol_name": "Aegis Multi-Collateral Liquidity Protocol",
                "sponsor_address": self.operator,
                "total_pool_usdc": 250000,
                "paid_bounties_usdc": 0,
                "max_critical_bounty_usdc": 100000,
                "max_medium_bounty_usdc": 25000,
                "authorized_telemetry_url": "https://metaremover.github.io/aegis-bug-bounty/demo/mock_cve_critical_reentrancy_patch.html",
                "is_active": True,
                "status": "ACTIVE_OPEN"
            }
        }
        self.bounty_reports: Dict[str, Dict[str, Any]] = {}
        self.disbursed_cves: Dict[str, bool] = {}
        self.disbursed_advisories: Dict[str, bool] = {}
        self.disbursed_content_hashes: Dict[str, bool] = {}

    def triage_report(self, report_id: str, program_id: str, researcher: str, advisory_url: str, cve_id: str, verdict: str, cvss_x10: int):
        assert report_id not in self.bounty_reports, f"[ERR_REPLAY_01] Report ID '{report_id}' already processed."
        assert program_id in self.programs, f"[ERR_PROGRAM_01] Program '{program_id}' not found."
        
        program = self.programs[program_id]
        advisory_key = f"{program_id}:{advisory_url.lower()}"
        assert advisory_key not in self.disbursed_advisories, f"[ERR_REPLAY_03] Advisory '{advisory_url}' already processed."

        if verdict in ("CRITICAL_EXPLOIT_VERIFIED", "MEDIUM_SEVERITY_APPROVED"):
            cve_key = f"{program_id}:{cve_id.upper()}"
            assert cve_key not in self.disbursed_cves, f"[ERR_REPLAY_02] Bounty for CVE '{cve_id}' in program '{program_id}' already claimed."

        bounty_amount = 0
        if verdict == "CRITICAL_EXPLOIT_VERIFIED":
            bounty_amount = min(program["max_critical_bounty_usdc"], program["total_pool_usdc"] - program["paid_bounties_usdc"])
        elif verdict == "MEDIUM_SEVERITY_APPROVED":
            bounty_amount = min(program["max_medium_bounty_usdc"], program["total_pool_usdc"] - program["paid_bounties_usdc"])

        if bounty_amount > 0:
            cve_key = f"{program_id}:{cve_id.upper()}"
            self.disbursed_cves[cve_key] = True
            self.disbursed_advisories[advisory_key] = True

        program["paid_bounties_usdc"] += bounty_amount
        self.bounty_reports[report_id] = {
            "report_id": report_id,
            "cve_identifier": cve_id,
            "verdict": verdict,
            "bounty": bounty_amount
        }
        return {"report_id": report_id, "bounty": bounty_amount, "verdict": verdict}


def test_aegis_replay_protection():
    logging.info("=" * 75)
    logging.info("  AEGIS BUG BOUNTY MULTI-LAYER REPLAY PROTECTION AUDIT (JOAQUIN)")
    logging.info("=" * 75)

    contract = MockAegisBugBounty("0x09FaE1AafADb0a3B8382E43Ed8d2d56Ba92171C3")
    researcher = "0x71546f55c131acd54cf93e181b9cabaeaf440fc3"

    # Test Vector 1: Submit Critical CVE-2026-8891
    res1 = contract.triage_report(
        report_id="REPORT_001",
        program_id="PROG_AEGIS_LENDING_01",
        researcher=researcher,
        advisory_url="https://metaremover.github.io/aegis-bug-bounty/demo/mock_cve_critical_reentrancy_patch.html",
        cve_id="CVE-2026-8891",
        verdict="CRITICAL_EXPLOIT_VERIFIED",
        cvss_x10=98
    )
    assert res1["bounty"] == 100000
    assert contract.programs["PROG_AEGIS_LENDING_01"]["paid_bounties_usdc"] == 100000
    logging.info(f"✓ 1. TC-01: Critical Exploit CVE-2026-8891 Triaged -> $100,000 Bounty Disbursed")

    # Test Vector 2: Replay same Report ID -> Reverts ERR_REPLAY_01
    try:
        contract.triage_report("REPORT_001", "PROG_AEGIS_LENDING_01", researcher, "https://other-url.com", "CVE-2026-9999", "CRITICAL_EXPLOIT_VERIFIED", 95)
        raise AssertionError("Expected ERR_REPLAY_01")
    except AssertionError as e:
        assert "[ERR_REPLAY_01]" in str(e)
        logging.info("✓ 2. TC-02: Duplicate Report ID Replay Blocked ([ERR_REPLAY_01])")

    # Test Vector 3: Re-submit SAME CVE under NEW Report ID -> Reverts ERR_REPLAY_02 (Joaquin Invariant)
    try:
        contract.triage_report("REPORT_002", "PROG_AEGIS_LENDING_01", "0x5C48c6f77617FC05761433Cc4019A79b47d1ec7D", "https://new-url.com/advisory.html", "CVE-2026-8891", "CRITICAL_EXPLOIT_VERIFIED", 98)
        raise AssertionError("Expected ERR_REPLAY_02")
    except AssertionError as e:
        assert "[ERR_REPLAY_02]" in str(e)
        logging.info("✓ 3. TC-03: Program-Bound CVE Double-Claim Blocked under new Report ID ([ERR_REPLAY_02])")

    # Test Vector 4: Re-submit SAME Advisory Feed URL -> Reverts ERR_REPLAY_03
    try:
        contract.triage_report("REPORT_003", "PROG_AEGIS_LENDING_01", researcher, "https://metaremover.github.io/aegis-bug-bounty/demo/mock_cve_critical_reentrancy_patch.html", "CVE-2026-9999", "CRITICAL_EXPLOIT_VERIFIED", 95)
        raise AssertionError("Expected ERR_REPLAY_03")
    except AssertionError as e:
        assert "[ERR_REPLAY_03]" in str(e)
        logging.info("✓ 4. TC-04: Re-submitted Advisory Feed URL Blocked ([ERR_REPLAY_03])")

    # Test Vector 5: Submit Medium Severity Issue (CVE-2026-8892)
    res2 = contract.triage_report(
        report_id="REPORT_004",
        program_id="PROG_AEGIS_LENDING_01",
        researcher=researcher,
        advisory_url="https://metaremover.github.io/aegis-bug-bounty/demo/mock_cve_medium_oracle_timeout.html",
        cve_id="CVE-2026-8892",
        verdict="MEDIUM_SEVERITY_APPROVED",
        cvss_x10=65
    )
    assert res2["bounty"] == 25000
    assert contract.programs["PROG_AEGIS_LENDING_01"]["paid_bounties_usdc"] == 125000
    logging.info("✓ 5. TC-05: Medium Severity CVE-2026-8892 Triaged -> $25,000 Bounty Disbursed (Total Paid: $125k / $250k)")

    logging.info("=" * 75)
    logging.info("  ALL JOAQUIN REPLAY PROTECTION INVARIANTS 100% VERIFIED AND PASSING!")
    logging.info("=" * 75)


if __name__ == "__main__":
    test_aegis_replay_protection()
