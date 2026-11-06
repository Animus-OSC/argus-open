import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "argus_receipt_schema_gate", Path(__file__).with_name("verify-receipt-schema.py")
)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class ReceiptSchemaCorpusTests(unittest.TestCase):
    def setUp(self):
        self.schema = json.loads((ROOT / "schemas/receipt-v1.schema.json").read_text())
        self.corpus = json.loads((ROOT / "pkg/evidence/testdata/receipt-wire-v1.json").read_text())

    def test_actual_corpus_has_required_controls(self):
        gate.validate_corpus(self.schema, self.corpus)

    def test_empty_corpus_is_blocked(self):
        self.corpus["cases"] = []
        with self.assertRaises(ValueError):
            gate.validate_corpus(self.schema, self.corpus)

    def test_missing_fail_base_is_blocked(self):
        del self.corpus["bases"]["fail"]
        with self.assertRaises(ValueError):
            gate.validate_corpus(self.schema, self.corpus)

    def test_malformed_base_receipt_is_blocked(self):
        for receipt in (None, [], "receipt", 0):
            with self.subTest(receipt=receipt):
                self.corpus["bases"]["pass"]["receipt"] = receipt
                with self.assertRaises(ValueError):
                    gate.validate_corpus(self.schema, self.corpus)

    def test_wrong_version_is_blocked(self):
        for version in (True, 0, 2, "1"):
            with self.subTest(version=version):
                self.corpus["version"] = version
                with self.assertRaises(ValueError):
                    gate.validate_corpus(self.schema, self.corpus)

    def test_missing_positive_control_is_blocked(self):
        self.corpus["cases"] = [c for c in self.corpus["cases"] if c["name"] != "valid_fail"]
        with self.assertRaises(ValueError):
            gate.validate_corpus(self.schema, self.corpus)

    def test_missing_required_null_control_is_blocked(self):
        self.corpus["cases"] = [
            c for c in self.corpus["cases"] if c["name"] != "null_receipt_observation_exit_code"
        ]
        with self.assertRaises(ValueError):
            gate.validate_corpus(self.schema, self.corpus)

    def test_null_control_cannot_be_replaced_by_zero(self):
        case = next(c for c in self.corpus["cases"] if c["name"] == "null_receipt_observation_exit_code")
        case["value"] = 0
        with self.assertRaises(ValueError):
            gate.validate_corpus(self.schema, self.corpus)

    def test_duplicate_names_are_blocked(self):
        self.corpus["cases"].append(copy.deepcopy(self.corpus["cases"][0]))
        with self.assertRaises(ValueError):
            gate.validate_corpus(self.schema, self.corpus)


if __name__ == "__main__":
    unittest.main()
