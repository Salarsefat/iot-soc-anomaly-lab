import re
import xml.etree.ElementTree as ET
from pathlib import Path

from iotsoc.detectors import RULES

XML = Path(__file__).resolve().parents[1] / "wazuh" / "rules" / "iotsoc_rules.xml"


def test_rules_file_is_well_formed_and_ids_in_range():
    root = ET.parse(XML).getroot()
    ids = [int(r.get("id")) for r in root.iter("rule")]
    assert len(ids) == len(set(ids))
    assert all(100600 <= i <= 100629 for i in ids)


def test_python_rule_mirror_matches_xml():
    text = XML.read_text()
    for rule_id in RULES:
        assert 'id="%s"' % rule_id in text
    assert re.search(r'id="100602" level="\d+" frequency="10" timeframe="300"', text)
    assert re.search(r'id="100608" level="\d+" frequency="20" timeframe="300"', text)
    assert RULES["100602"][1] == 10 and RULES["100608"][1] == 20


def test_frequency_parents_are_not_level_zero():
    """Wazuh 4.14.7 did not correlate frequency rules on level-0 parents."""
    root = ET.parse(XML).getroot()
    levels = {r.get("id"): int(r.get("level")) for r in root.iter("rule")}
    for rule in root.iter("rule"):
        if rule.get("frequency"):
            for parent in rule.find("if_matched_sid").text.split(","):
                assert levels[parent.strip()] > 0
