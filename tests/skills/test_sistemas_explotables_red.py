"""Unit tests for sistemas_explotables_red skill helper logic."""

import json
from typing import Dict, Any
from unittest.mock import MagicMock, patch

from drystone.skills.sistemas_explotables_red import SistemasExplotablesRedSkill
from drystone.validation.pre_checks import check_ser_cve_001


def test_build_reachability_includes_alb_to_ecs_edge_for_public_alb() -> None:
    skill = SistemasExplotablesRedSkill()
    front_doors = {
        "load_balancers": [
            {
                "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/public/abc",
                "Scheme": "internet-facing",
            }
        ],
        "listeners": [],
        "target_groups": [
            {
                "TargetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/tg-1/def",
                "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/public/abc",
            }
        ],
        "lambda_function_urls": [],
        "api_gateway_routes": [],
    }
    compute_inventory = {
        "ec2_instances": [],
        "lambda_functions": [],
        "rds_instances": [],
        "ecs_services": [
            {
                "ServiceArn": "arn:aws:ecs:us-east-1:123:service/cluster/service-a",
                "LoadBalancers": [
                    {
                        "targetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/tg-1/def"
                    }
                ],
            }
        ],
    }

    reachability, _ = skill._build_reachability(
        front_doors=front_doors, compute_inventory=compute_inventory
    )
    edges = reachability.get("edges", [])
    assert any(
        isinstance(e, dict)
        and e.get("path_type") == "alb->ecs-service"
        and e.get("target") == "arn:aws:ecs:us-east-1:123:service/cluster/service-a"
        for e in edges
    )


def test_build_attack_paths_scores_high_when_vuln_and_blast_radius_present() -> None:
    skill = SistemasExplotablesRedSkill()
    reachability_doc = {
        "edges": [
            {
                "source": "internet",
                "target": "arn:aws:ec2:*:*:instance/i-123",
                "confidence": 0.9,
            }
        ]
    }
    inspector_doc = {
        "findings": [
            {
                "severity": "HIGH",
                "resources": [{"id": "arn:aws:ec2:*:*:instance/i-123", "type": "AWS_EC2_INSTANCE"}],
            },
            {
                "severity": "CRITICAL",
                "resources": [{"id": "arn:aws:ec2:*:*:instance/i-123", "type": "AWS_EC2_INSTANCE"}],
            },
        ]
    }
    compute_inventory = {
        "ec2_instances": [
            {
                "InstanceId": "i-123",
                "IamInstanceProfile": {"Arn": "arn:aws:iam::123:instance-profile/prof-a"},
            }
        ],
        "lambda_functions": [],
    }

    paths = skill._build_attack_paths(
        reachability_doc=reachability_doc,
        inspector_doc=inspector_doc,
        compute_inventory=compute_inventory,
    )
    assert len(paths) == 1
    assert paths[0]["overall_score"] >= 0.75


def test_build_reachability_uses_real_region_account_in_arns() -> None:
    """B2: EC2 ARNs should use real region and account_id instead of wildcards."""
    skill = SistemasExplotablesRedSkill()
    front_doors = {
        "load_balancers": [],
        "listeners": [],
        "target_groups": [],
        "lambda_function_urls": [],
        "api_gateway_routes": [],
    }
    compute_inventory = {
        "ec2_instances": [
            {
                "InstanceId": "i-real123",
                "PublicIpAddress": "1.2.3.4",
                "SecurityGroups": [],
            }
        ],
        "ecs_services": [],
        "lambda_functions": [],
        "rds_instances": [],
    }

    reachability, _ = skill._build_reachability(
        front_doors=front_doors,
        compute_inventory=compute_inventory,
        region="us-east-1",
        account_id="111122223333",
    )
    edges = reachability.get("edges", [])
    assert len(edges) == 1
    assert edges[0]["target"] == "arn:aws:ec2:us-east-1:111122223333:instance/i-real123"
    assert "*" not in edges[0]["target"]


def test_build_attack_paths_severity_mapping() -> None:
    """D2: overall_score maps to the correct severity label."""
    skill = SistemasExplotablesRedSkill()
    assert skill._overall_score_to_severity(0.9) == "Critical"
    assert skill._overall_score_to_severity(0.75) == "Critical"
    assert skill._overall_score_to_severity(0.74) == "High"
    assert skill._overall_score_to_severity(0.55) == "High"
    assert skill._overall_score_to_severity(0.54) == "Medium"
    assert skill._overall_score_to_severity(0.35) == "Medium"
    assert skill._overall_score_to_severity(0.34) == "Low"
    assert skill._overall_score_to_severity(0.0) == "Low"


def test_build_attack_paths_includes_severity_field() -> None:
    """D2: attack paths must include a severity field derived from overall_score."""
    skill = SistemasExplotablesRedSkill()
    reachability_doc = {
        "edges": [
            {
                "source": "internet",
                "target": "arn:aws:ec2:us-east-1:123:instance/i-sev",
                "confidence": 0.9,
            }
        ]
    }
    inspector_doc = {
        "findings": [
            {
                "severity": "CRITICAL",
                "resources": [{"id": "i-sev", "type": "AWS_EC2_INSTANCE"}],
            }
        ]
    }
    compute_inventory = {
        "ec2_instances": [
            {"InstanceId": "i-sev", "IamInstanceProfile": {"Arn": "arn:aws:iam::123:ip/p"}}
        ],
        "lambda_functions": [],
    }

    paths = skill._build_attack_paths(
        reachability_doc=reachability_doc,
        inspector_doc=inspector_doc,
        compute_inventory=compute_inventory,
    )
    assert len(paths) == 1
    assert "severity" in paths[0]
    assert paths[0]["severity"] in ("Critical", "High", "Medium", "Low")
    # With CRITICAL inspector signal + IAM role, score should be high -> Critical
    assert paths[0]["severity"] == "Critical"


def test_build_attack_paths_matches_ec2_short_id_from_inspector() -> None:
    skill = SistemasExplotablesRedSkill()
    reachability_doc = {
        "edges": [
            {
                "source": "internet",
                "target": "arn:aws:ec2:*:*:instance/i-abc123",
                "confidence": 0.9,
            }
        ]
    }
    inspector_doc = {
        "findings": [
            {
                "severity": "MEDIUM",
                "title": "Port 22 is reachable from an Internet Gateway - TCP",
                "resources": [{"id": "i-abc123", "type": "AWS_EC2_INSTANCE"}],
            }
        ]
    }
    compute_inventory = {
        "ec2_instances": [
            {
                "InstanceId": "i-abc123",
                "IamInstanceProfile": {"Arn": "arn:aws:iam::123:instance-profile/prof-a"},
            }
        ],
        "lambda_functions": [],
    }

    paths = skill._build_attack_paths(
        reachability_doc=reachability_doc,
        inspector_doc=inspector_doc,
        compute_inventory=compute_inventory,
    )
    assert len(paths) == 1
    assert paths[0]["vulnerability_score"] >= 0.55
    assert paths[0]["inspector_signal"]["internet_reachability_findings"] == 1


class TestCollectCveIntelligence:
    """Tests for _collect_cve_intelligence() — mocks urllib to avoid real network calls."""

    def _make_skill(self) -> SistemasExplotablesRedSkill:
        return SistemasExplotablesRedSkill()

    def _inspector_doc_with_ec2_cve(self) -> dict:
        return {
            "findings": [
                {
                    "severity": "HIGH",
                    "status": "ACTIVE",
                    "title": "CVE-2024-26130 cryptography 41.0.4",
                    "resources": [{"id": "i-ec2abc", "type": "AWS_EC2_INSTANCE"}],
                }
            ]
        }

    def _network_controls_with_open_ssh(self) -> dict:
        return {
            "security_groups": [
                {
                    "GroupId": "sg-open",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ]
        }

    def _compute_inventory_with_public_ec2(self) -> dict:
        return {
            "ec2_instances": [
                {
                    "InstanceId": "i-ec2abc",
                    "PublicIpAddress": "1.2.3.4",
                    "SecurityGroups": [{"GroupId": "sg-open"}],
                }
            ]
        }

    def test_returns_expected_structure(self) -> None:
        skill = self._make_skill()
        result = skill._collect_cve_intelligence({}, {}, {})
        assert "instances" in result
        assert "enrichment_timestamp" in result
        assert "enrichment_errors" in result

    def test_empty_inspector_produces_empty_instances(self) -> None:
        skill = self._make_skill()
        result = skill._collect_cve_intelligence({"findings": []}, {}, {})
        assert result["instances"] == {}

    @patch("urllib.request.urlopen")
    def test_nvd_enrichment_populates_cvss(self, mock_urlopen: MagicMock) -> None:
        """When NVD returns CVSS data, it should be stored in the CVE entry."""
        nvd_response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                    }
                                }
                            ]
                        }
                    }
                }
            ]
        }
        mock_cm = MagicMock()
        mock_cm.__enter__ = MagicMock(return_value=mock_cm)
        mock_cm.__exit__ = MagicMock(return_value=False)
        mock_cm.read.return_value = json.dumps(nvd_response).encode()
        mock_urlopen.return_value = mock_cm

        skill = self._make_skill()
        result = skill._collect_cve_intelligence(
            inspector_doc=self._inspector_doc_with_ec2_cve(),
            network_controls=self._network_controls_with_open_ssh(),
            compute_inventory=self._compute_inventory_with_public_ec2(),
        )
        instances = result["instances"]
        assert "i-ec2abc" in instances
        cves = instances["i-ec2abc"]["cves"]
        assert len(cves) >= 1
        assert cves[0]["cvss_score"] == 7.5
        assert cves[0]["attack_vector"] == "NETWORK"
        assert cves[0]["exploitable_from_internet"] is True

    @patch("urllib.request.urlopen", side_effect=Exception("NVD unreachable"))
    def test_nvd_failure_is_graceful(self, _mock: MagicMock) -> None:
        """NVD errors should be recorded in enrichment_errors, not raise."""
        skill = self._make_skill()
        result = skill._collect_cve_intelligence(
            inspector_doc=self._inspector_doc_with_ec2_cve(),
            network_controls={},
            compute_inventory={},
        )
        assert len(result["enrichment_errors"]) >= 1
        assert (
            "NVD" in result["enrichment_errors"][0]
            or "unreachable" in result["enrichment_errors"][0]
        )

    def test_attack_path_generated_for_public_ec2(self) -> None:
        skill = self._make_skill()
        result = skill._collect_cve_intelligence(
            inspector_doc=self._inspector_doc_with_ec2_cve(),
            network_controls=self._network_controls_with_open_ssh(),
            compute_inventory=self._compute_inventory_with_public_ec2(),
        )
        instances = result["instances"]
        assert "i-ec2abc" in instances
        attack_path = instances["i-ec2abc"]["attack_path"]
        assert "steps" in attack_path
        assert len(attack_path["steps"]) >= 3
        # First step should reference internet reachability
        assert attack_path["steps"][0]["technique"] in ("T1595.001", "T1190")

    def test_open_ports_populated_for_public_ec2(self) -> None:
        skill = self._make_skill()
        result = skill._collect_cve_intelligence(
            inspector_doc=self._inspector_doc_with_ec2_cve(),
            network_controls=self._network_controls_with_open_ssh(),
            compute_inventory=self._compute_inventory_with_public_ec2(),
        )
        open_ports = result["instances"]["i-ec2abc"]["open_ports"]
        assert any(p["port"] == 22 for p in open_ports)


# ── Exploit Enrichment Tests ──────────────────────────────────


def _mock_urlopen_context(data: bytes) -> MagicMock:
    """Create a mock context manager for urllib.request.urlopen."""
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=cm)
    cm.__exit__ = MagicMock(return_value=False)
    cm.read = MagicMock(return_value=data)
    return cm


_SAMPLE_KEV_JSON = {
    "title": "CISA KEV Catalog",
    "catalogVersion": "2026.04.01",
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-26130",
            "vendorProject": "cryptography.io",
            "product": "cryptography",
            "dateAdded": "2025-06-15",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2023-99999",
            "vendorProject": "Fake",
            "product": "FakeProduct",
            "dateAdded": "2024-01-01",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}

_SAMPLE_EDB_CSV = (
    "id,file,description,date_published,author,platform,type,port,codes\n"
    '51234,exploits/linux/remote/51234.py,"OpenSSH RCE",2024-03-15,researcher,linux,remote,22,CVE-2024-26130;OSVDB-12345\n'
    '51235,exploits/windows/local/51235.py,"Windows LPE",2024-04-01,author2,windows,local,0,CVE-2024-99999\n'
)


class TestExploitEnrichment:
    """Tests for CISA KEV, Exploit-DB, and exploit_intel enrichment."""

    def _make_skill(self) -> SistemasExplotablesRedSkill:
        s = SistemasExplotablesRedSkill()
        # Clear caches between tests
        if hasattr(s, "_kev_cache"):
            del s._kev_cache
        if hasattr(s, "_edb_cache"):
            del s._edb_cache
        return s

    # ── CISA KEV tests ────────────────────────────────────────

    @patch("urllib.request.urlopen")
    def test_fetch_cisa_kev_returns_dict_keyed_by_cve(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _mock_urlopen_context(
            json.dumps(_SAMPLE_KEV_JSON).encode()
        )
        skill = self._make_skill()
        result = skill._fetch_cisa_kev()
        assert "CVE-2024-26130" in result
        assert result["CVE-2024-26130"]["vendor"] == "cryptography.io"
        assert result["CVE-2024-26130"]["ransomware_use"] == "Known"

    @patch("urllib.request.urlopen", side_effect=TimeoutError("connect timed out"))
    def test_fetch_cisa_kev_graceful_on_timeout(self, _mock: MagicMock) -> None:
        skill = self._make_skill()
        result = skill._fetch_cisa_kev()
        assert result == {}

    @patch("urllib.request.urlopen")
    def test_fetch_cisa_kev_graceful_on_invalid_json(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _mock_urlopen_context(b"not json!!!")
        skill = self._make_skill()
        result = skill._fetch_cisa_kev()
        assert result == {}

    # ── Exploit-DB tests ──────────────────────────────────────

    @patch("urllib.request.urlopen")
    def test_fetch_exploitdb_csv_returns_matches(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _mock_urlopen_context(_SAMPLE_EDB_CSV.encode())
        skill = self._make_skill()
        result = skill._fetch_exploitdb_index({"CVE-2024-26130"})
        assert "CVE-2024-26130" in result
        assert result["CVE-2024-26130"]["id"] == 51234
        assert result["CVE-2024-26130"]["type"] == "remote"
        assert result["CVE-2024-26130"]["platform"] == "linux"

    @patch("urllib.request.urlopen")
    def test_fetch_exploitdb_csv_no_match(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _mock_urlopen_context(_SAMPLE_EDB_CSV.encode())
        skill = self._make_skill()
        result = skill._fetch_exploitdb_index({"CVE-2099-00001"})
        assert "CVE-2099-00001" not in result

    @patch("urllib.request.urlopen", side_effect=TimeoutError("read timed out"))
    def test_fetch_exploitdb_csv_graceful_on_timeout(self, _mock: MagicMock) -> None:
        skill = self._make_skill()
        result = skill._fetch_exploitdb_index({"CVE-2024-26130"})
        assert result == {}

    @patch("urllib.request.urlopen")
    def test_exploitdb_codes_field_with_multiple_cves(self, mock_urlopen: MagicMock) -> None:
        """One exploit row maps to two CVEs via ;-separated codes field."""
        mock_urlopen.return_value = _mock_urlopen_context(_SAMPLE_EDB_CSV.encode())
        skill = self._make_skill()
        result = skill._fetch_exploitdb_index({"CVE-2024-26130", "CVE-2024-99999"})
        # First row maps CVE-2024-26130, second row maps CVE-2024-99999
        assert "CVE-2024-26130" in result
        assert "CVE-2024-99999" in result

    # ── NVD PoC URL extraction ────────────────────────────────

    @patch("urllib.request.urlopen")
    def test_nvd_references_extracts_poc_urls(self, mock_urlopen: MagicMock) -> None:
        """NVD refs with Exploit tag or PoC domains should populate poc_urls."""
        nvd_resp = {
            "vulnerabilities": [{
                "cve": {
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
                    "descriptions": [{"lang": "en", "value": "Test CVE"}],
                    "references": [
                        {"url": "https://github.com/user/CVE-2024-26130-poc", "tags": ["Exploit"]},
                        {"url": "https://www.exploit-db.com/exploits/51234", "tags": []},
                        {"url": "https://vendor.com/advisory", "tags": ["Vendor Advisory"]},
                    ],
                }
            }]
        }
        mock_urlopen.return_value = _mock_urlopen_context(json.dumps(nvd_resp).encode())
        skill = self._make_skill()
        # Need KEV/EDB caches to avoid those HTTP calls
        skill._kev_cache = {}
        skill._edb_cache = {}
        result = skill._collect_cve_intelligence(
            inspector_doc={"findings": [{"severity": "HIGH", "title": "CVE-2024-26130 pkg", "resources": [{"id": "i-test", "type": "AWS_EC2_INSTANCE"}]}]},
            network_controls={},
            compute_inventory={},
        )
        cves = result["instances"]["i-test"]["cves"]
        poc_urls = cves[0]["exploit_intel"]["poc_urls"]
        assert "https://github.com/user/CVE-2024-26130-poc" in poc_urls
        assert "https://www.exploit-db.com/exploits/51234" in poc_urls
        assert "https://vendor.com/advisory" not in poc_urls

    @patch("urllib.request.urlopen")
    def test_nvd_references_filters_non_poc_urls(self, mock_urlopen: MagicMock) -> None:
        nvd_resp = {
            "vulnerabilities": [{
                "cve": {
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0, "vectorString": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"}}]},
                    "descriptions": [{"lang": "en", "value": "Low risk"}],
                    "references": [
                        {"url": "https://vendor.com/advisory", "tags": ["Vendor Advisory"]},
                        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-26130", "tags": []},
                    ],
                }
            }]
        }
        mock_urlopen.return_value = _mock_urlopen_context(json.dumps(nvd_resp).encode())
        skill = self._make_skill()
        skill._kev_cache = {}
        skill._edb_cache = {}
        result = skill._collect_cve_intelligence(
            inspector_doc={"findings": [{"severity": "HIGH", "title": "CVE-2024-26130 pkg", "resources": [{"id": "i-test", "type": "AWS_EC2_INSTANCE"}]}]},
            network_controls={},
            compute_inventory={},
        )
        poc_urls = result["instances"]["i-test"]["cves"][0]["exploit_intel"]["poc_urls"]
        assert poc_urls == []

    @patch("urllib.request.urlopen")
    def test_nvd_poc_urls_deduplicated(self, mock_urlopen: MagicMock) -> None:
        nvd_resp = {
            "vulnerabilities": [{
                "cve": {
                    "metrics": {},
                    "descriptions": [],
                    "references": [
                        {"url": "https://github.com/dup-poc", "tags": ["Exploit"]},
                        {"url": "https://github.com/dup-poc", "tags": ["Third Party Advisory"]},
                    ],
                }
            }]
        }
        mock_urlopen.return_value = _mock_urlopen_context(json.dumps(nvd_resp).encode())
        skill = self._make_skill()
        skill._kev_cache = {}
        skill._edb_cache = {}
        result = skill._collect_cve_intelligence(
            inspector_doc={"findings": [{"severity": "HIGH", "title": "CVE-2024-26130 pkg", "resources": [{"id": "i-test", "type": "AWS_EC2_INSTANCE"}]}]},
            network_controls={},
            compute_inventory={},
        )
        poc_urls = result["instances"]["i-test"]["cves"][0]["exploit_intel"]["poc_urls"]
        assert poc_urls.count("https://github.com/dup-poc") == 1

    # ── exploit_intel dict tests ──────────────────────────────

    def test_exploit_intel_has_public_exploit_true_when_kev_listed(self) -> None:
        skill = self._make_skill()
        skill._kev_cache = {"CVE-2024-26130": {"date_added": "2025-06-15", "vendor": "x", "product": "y", "ransomware_use": "Known"}}
        skill._edb_cache = {}
        with patch("urllib.request.urlopen", side_effect=Exception("skip NVD")):
            result = skill._collect_cve_intelligence(
                inspector_doc={"findings": [{"severity": "HIGH", "title": "CVE-2024-26130 pkg", "resources": [{"id": "i-test", "type": "AWS_EC2_INSTANCE"}]}]},
                network_controls={},
                compute_inventory={},
            )
        intel = result["instances"]["i-test"]["cves"][0]["exploit_intel"]
        assert intel["has_public_exploit"] is True
        assert intel["cisa_kev"]["listed"] is True

    def test_exploit_intel_has_public_exploit_true_when_exploitdb_match(self) -> None:
        skill = self._make_skill()
        skill._kev_cache = {}
        skill._edb_cache = {"CVE-2024-26130": {"id": 51234, "type": "remote", "platform": "linux", "description": "test"}}
        with patch("urllib.request.urlopen", side_effect=Exception("skip NVD")):
            result = skill._collect_cve_intelligence(
                inspector_doc={"findings": [{"severity": "HIGH", "title": "CVE-2024-26130 pkg", "resources": [{"id": "i-test", "type": "AWS_EC2_INSTANCE"}]}]},
                network_controls={},
                compute_inventory={},
            )
        intel = result["instances"]["i-test"]["cves"][0]["exploit_intel"]
        assert intel["has_public_exploit"] is True
        assert intel["exploit_db"]["id"] == 51234

    def test_exploit_intel_has_public_exploit_false_when_no_sources(self) -> None:
        skill = self._make_skill()
        skill._kev_cache = {}
        skill._edb_cache = {}
        with patch("urllib.request.urlopen", side_effect=Exception("skip NVD")):
            result = skill._collect_cve_intelligence(
                inspector_doc={"findings": [{"severity": "HIGH", "title": "CVE-2024-26130 pkg", "resources": [{"id": "i-test", "type": "AWS_EC2_INSTANCE"}]}]},
                network_controls={},
                compute_inventory={},
            )
        intel = result["instances"]["i-test"]["cves"][0]["exploit_intel"]
        assert intel["has_public_exploit"] is False

    def test_exploit_intel_summary_mentions_kev_and_exploitdb(self) -> None:
        skill = self._make_skill()
        skill._kev_cache = {"CVE-2024-26130": {"date_added": "2025-06-15", "vendor": "x", "product": "y", "ransomware_use": "Unknown"}}
        skill._edb_cache = {"CVE-2024-26130": {"id": 51234, "type": "remote", "platform": "linux", "description": "test"}}
        with patch("urllib.request.urlopen", side_effect=Exception("skip NVD")):
            result = skill._collect_cve_intelligence(
                inspector_doc={"findings": [{"severity": "HIGH", "title": "CVE-2024-26130 pkg", "resources": [{"id": "i-test", "type": "AWS_EC2_INSTANCE"}]}]},
                network_controls={},
                compute_inventory={},
            )
        summary = result["instances"]["i-test"]["cves"][0]["exploit_intel"]["summary"]
        assert "CISA KEV" in summary
        assert "Exploit-DB" in summary

    def test_exploit_intel_combined_with_existing_cve_fields(self) -> None:
        skill = self._make_skill()
        skill._kev_cache = {}
        skill._edb_cache = {}
        with patch("urllib.request.urlopen", side_effect=Exception("skip NVD")):
            result = skill._collect_cve_intelligence(
                inspector_doc={"findings": [{"severity": "CRITICAL", "title": "CVE-2024-26130 openssh", "resources": [{"id": "i-test", "type": "AWS_EC2_INSTANCE"}]}]},
                network_controls={},
                compute_inventory={},
            )
        cve = result["instances"]["i-test"]["cves"][0]
        # Existing fields still present
        assert cve["id"] == "CVE-2024-26130"
        assert cve["package"] == "openssh"
        assert "attack_vector" in cve
        # New exploit_intel field present
        assert "exploit_intel" in cve
        assert "has_public_exploit" in cve["exploit_intel"]

    def test_enrichment_skipped_when_no_inspector_findings(self) -> None:
        skill = self._make_skill()
        skill._kev_cache = {"CVE-9999-9999": {"date_added": "x", "vendor": "x", "product": "x", "ransomware_use": "Unknown"}}
        skill._edb_cache = {}
        result = skill._collect_cve_intelligence(
            inspector_doc={"findings": []},
            network_controls={},
            compute_inventory={},
        )
        assert result["instances"] == {}

    def test_kev_ransomware_use_propagated(self) -> None:
        skill = self._make_skill()
        skill._kev_cache = {"CVE-2024-26130": {"date_added": "2025-06-15", "vendor": "x", "product": "y", "ransomware_use": "Known"}}
        skill._edb_cache = {}
        with patch("urllib.request.urlopen", side_effect=Exception("skip NVD")):
            result = skill._collect_cve_intelligence(
                inspector_doc={"findings": [{"severity": "HIGH", "title": "CVE-2024-26130 pkg", "resources": [{"id": "i-test", "type": "AWS_EC2_INSTANCE"}]}]},
                network_controls={},
                compute_inventory={},
            )
        kev = result["instances"]["i-test"]["cves"][0]["exploit_intel"]["cisa_kev"]
        assert kev["ransomware_use"] == "Known"

    @patch("urllib.request.urlopen")
    def test_kev_cache_reused_across_cves(self, mock_urlopen: MagicMock) -> None:
        """_fetch_cisa_kev should only be called once regardless of CVE count."""
        mock_urlopen.return_value = _mock_urlopen_context(
            json.dumps(_SAMPLE_KEV_JSON).encode()
        )
        skill = self._make_skill()
        # First call fetches
        result1 = skill._fetch_cisa_kev()
        # Second call should use cache (no new urlopen call)
        call_count = mock_urlopen.call_count
        result2 = skill._fetch_cisa_kev()
        assert mock_urlopen.call_count == call_count  # no new call
        assert result1 == result2

    def test_all_sources_fail_gracefully(self) -> None:
        """When KEV, EDB, and NVD all fail, enrichment should still complete."""
        skill = self._make_skill()
        with patch("urllib.request.urlopen", side_effect=TimeoutError("all down")):
            result = skill._collect_cve_intelligence(
                inspector_doc={"findings": [{"severity": "HIGH", "title": "CVE-2024-26130 pkg", "resources": [{"id": "i-test", "type": "AWS_EC2_INSTANCE"}]}]},
                network_controls={},
                compute_inventory={},
            )
        assert "i-test" in result["instances"]
        intel = result["instances"]["i-test"]["cves"][0]["exploit_intel"]
        assert intel["has_public_exploit"] is False
        assert len(result["enrichment_errors"]) >= 1


# ── Pre-Check SER-CVE-001 Tests ──────────────────────────────


class TestPreCheckSerCve001:
    def test_fail_when_kev_cve_on_internet_exposed_instance(self) -> None:
        evidence = {
            "cve-intelligence": {
                "instances": {
                    "i-abc123": {
                        "cves": [{
                            "id": "CVE-2024-26130",
                            "exploitable_from_internet": True,
                            "exploit_intel": {"cisa_kev": {"listed": True}},
                        }],
                    }
                }
            }
        }
        r = check_ser_cve_001(evidence)
        assert r.status == "FAIL"
        assert "i-abc123" in r.affected_resources[0]

    def test_pass_when_kev_cve_but_not_internet_exposed(self) -> None:
        evidence = {
            "cve-intelligence": {
                "instances": {
                    "i-abc123": {
                        "cves": [{
                            "id": "CVE-2024-26130",
                            "exploitable_from_internet": False,
                            "exploit_intel": {"cisa_kev": {"listed": True}},
                        }],
                    }
                }
            }
        }
        r = check_ser_cve_001(evidence)
        assert r.status == "PASS"

    def test_pass_when_no_kev_cves(self) -> None:
        evidence = {
            "cve-intelligence": {
                "instances": {
                    "i-abc123": {
                        "cves": [{
                            "id": "CVE-2024-26130",
                            "exploitable_from_internet": True,
                            "exploit_intel": {"cisa_kev": {"listed": False}},
                        }],
                    }
                }
            }
        }
        r = check_ser_cve_001(evidence)
        assert r.status == "PASS"

    def test_skip_when_no_cve_intelligence_evidence(self) -> None:
        r = check_ser_cve_001({})
        assert r.status == "SKIP"
