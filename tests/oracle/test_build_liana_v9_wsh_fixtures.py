import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BUILDER = Path(__file__).with_name("build_liana_v9_wsh_fixtures.py")
CASE_IDS = ["legacy-single-primary-recovery", "legacy-2-of-3-primary-recovery", "legacy-multiple-recovery"]


class LegacyWshFixtureBuilderTests(unittest.TestCase):
    def test_rejects_duplicate_branch_index_rows(self) -> None:
        rows = []
        for case_id in CASE_IDS:
            rows.append(f"D\t{case_id}\twsh(example)")
            for branch in ("receive", "change"):
                for index in ("0", "1"):
                    rows.append(f"V\t{case_id}\t{branch}\t{index}\tbc1qexample\t0020deadbeef")
        rows.append("V\tlegacy-single-primary-recovery\treceive\t0\tbc1qduplicate\t0020deadbeef")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "vectors.tsv"
            source.write_text("\n".join(rows) + "\n")
            result = subprocess.run(
                [sys.executable, str(BUILDER), str(source), str(root / "fixtures")],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate vector row", result.stderr)


if __name__ == "__main__":
    unittest.main()
