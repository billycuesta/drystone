"""Tests for drystone.analysis.prioritizer.score_chunk (rec AG: previously untested)."""

from drystone.analysis.prioritizer import score_chunk

FILE_PRIORITY_VPCS = 82
FILE_PRIORITY_USERS = 76


class TestScoreChunkBasePriority:
    def test_known_file_uses_its_file_priority(self):
        assert score_chunk("inspector-findings", {}) == 100
        assert score_chunk("security-groups", {}) == 95

    def test_unknown_file_uses_default_priority(self):
        assert score_chunk("some-unlisted-file", {}) == 50

    def test_lookup_key_strips_json_suffix_and_lowercases(self):
        assert score_chunk("Security-Groups.json", {}) == 95


class TestScoreChunkDistilledBonus:
    def test_distilled_dict_adds_five(self):
        evidence = {"vpcs": {"_distilled": True, "items": []}}
        assert score_chunk("vpcs", evidence) == FILE_PRIORITY_VPCS + 5

    def test_non_distilled_dict_gets_no_bonus(self):
        evidence = {"vpcs": {"items": []}}
        assert score_chunk("vpcs", evidence) == FILE_PRIORITY_VPCS


class TestScoreChunkListBonus:
    def test_list_length_added_up_to_cap(self):
        evidence = {"users": [{"UserName": f"u{i}"} for i in range(5)]}
        assert score_chunk("users", evidence) == FILE_PRIORITY_USERS + 5

    def test_list_length_bonus_capped_at_twenty(self):
        evidence = {"users": [{"UserName": f"u{i}"} for i in range(50)]}
        assert score_chunk("users", evidence) == FILE_PRIORITY_USERS + 20


class TestScoreChunkItemsListBonus:
    def test_dict_with_items_list_adds_length_up_to_cap(self):
        evidence = {"vpcs": {"items": [{"VpcId": f"vpc-{i}"} for i in range(3)]}}
        assert score_chunk("vpcs", evidence) == FILE_PRIORITY_VPCS + 3

    def test_dict_items_list_bonus_capped_at_twenty(self):
        evidence = {"vpcs": {"items": [{"VpcId": f"vpc-{i}"} for i in range(50)]}}
        assert score_chunk("vpcs", evidence) == FILE_PRIORITY_VPCS + 20

    def test_distilled_dict_and_items_bonus_both_apply(self):
        evidence = {"vpcs": {"_distilled": True, "items": [{"VpcId": "vpc-1"}]}}
        assert score_chunk("vpcs", evidence) == FILE_PRIORITY_VPCS + 5 + 1


class TestScoreChunkMissingOrUnrelatedEvidence:
    def test_source_file_not_in_evidence_returns_base_priority_only(self):
        assert score_chunk("vpcs", {}) == FILE_PRIORITY_VPCS

    def test_evidence_lookup_uses_raw_source_file_not_normalized_key(self):
        """score_chunk() normalizes source_file (strip .json, lowercase) only for the
        FILE_PRIORITY lookup -- the evidence dict lookup uses the raw, unnormalized
        source_file. A mismatched case/suffix means the size bonus silently doesn't
        apply, even though the file-priority base score still resolves correctly.
        """
        evidence = {"vpcs": [{"VpcId": "vpc-1"}]}
        assert score_chunk("VPCs.json", evidence) == FILE_PRIORITY_VPCS
