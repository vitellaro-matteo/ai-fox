"""The offline mode must never touch the network: it only reads snapshot files."""

import json

from radar.sources import epss, kev
from radar.sources.fetcher import Fetcher


def test_offline_reads_snapshot_file(tmp_path):
    (tmp_path / "kev").mkdir()
    (tmp_path / "kev" / "known_exploited_vulnerabilities.json").write_text(
        json.dumps({"catalogVersion": "test", "vulnerabilities": []}), encoding="utf-8"
    )
    fetcher = Fetcher(tmp_path, offline=True)

    assert kev.load_kev(fetcher) == ("test", [])
    assert fetcher.requests_made == 0


def test_offline_missing_file_is_none_not_an_error(tmp_path):
    fetcher = Fetcher(tmp_path, offline=True)

    assert fetcher.get_json("https://example.invalid/x", "missing.json") is None
    assert kev.load_kev(fetcher) is None
    assert epss.load_epss(fetcher, ["CVE-2000-0001"]) == []
    assert fetcher.requests_made == 0
