"""Trusted driver for a fixed public profile; no project-supplied CLI paths.

JSON is local process evidence, not authentication. The caller must bind the
source bytes, expected test identities, process outcome and sandbox boundary.
"""

import contextlib
import json
import sys
import traceback
import unittest


class RecordingResult(unittest.TestResult):
    _priority = {"PASS": 0, "SKIP": 1, "XFAIL": 2, "XPASS": 3, "FAIL": 4, "ERROR": 5}

    def __init__(self):
        super().__init__()
        self.records = []
        self._current = None
        self._status = None
        self.lifecycle_complete = True

    def startTest(self, test):
        super().startTest(test)
        if self._current is not None:
            self.lifecycle_complete = False
        self._current = test.id()
        self._status = None

    def _outcome(self, status):
        if self._current is None:
            # Class/module fixture errors have no started test. Do not invent
            # a successful record for tests which never ran.
            self.lifecycle_complete = False
        elif self._status is None or self._priority[status] > self._priority[self._status]:
            self._status = status

    def stopTest(self, test):
        if self._current != test.id() or self._status is None:
            self.lifecycle_complete = False
        elif self._current is not None:
            self.records.append({"id": self._current, "status": self._status})
        self._current = None
        self._status = None
        super().stopTest(test)

    def addSuccess(self, test):
        super().addSuccess(test)
        self._outcome("PASS")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._outcome("FAIL")

    def addError(self, test, err):
        super().addError(test, err)
        self._outcome("ERROR")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._outcome("SKIP")

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self._outcome("XFAIL")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self._outcome("XPASS")

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self._outcome("FAIL" if issubclass(err[0], test.failureException) else "ERROR")


def _test_ids(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from _test_ids(test)
        else:
            yield test.id()


def run_suite(start, top):
    """Internal helper for driver regression fixtures; CLI paths stay fixed."""
    report = {
        "version": "argus.unittest/v1",
        "python_version": ".".join(map(str, sys.version_info[:3])),
        "discovered_ids": [],
        "records": [],
        "completed": False,
    }
    result = RecordingResult()
    # Discovery can execute imports and load_tests, so redirect before either.
    # The pinned source allowlist is still required: this is not a sandbox.
    with contextlib.redirect_stdout(sys.stderr):
        try:
            suite = unittest.TestLoader().discover(start, pattern="test_*.py", top_level_dir=top)
            report["discovered_ids"] = list(_test_ids(suite))
            suite.run(result)
            report["records"] = result.records
            report["completed"] = (
                result.lifecycle_complete
                and result._current is None
                and result.testsRun == len(report["discovered_ids"])
                and len(result.records) == len(report["discovered_ids"])
                and len(set(report["discovered_ids"])) == len(report["discovered_ids"])
                and {r["id"] for r in result.records} == set(report["discovered_ids"])
            )
        except BaseException:
            report["records"] = result.records
            traceback.print_exc(file=sys.stderr)
        finally:
            # The sandbox caller bounds stderr. Keep structured JSON unchanged
            # while retaining the actual unittest failure/error diagnostics.
            for status, entries in (("FAIL", result.failures), ("ERROR", result.errors)):
                for test, detail in entries:
                    print(status + ": " + test.id(), file=sys.stderr)
                    sys.stderr.write(detail)
    if not report["completed"]:
        return report, 3
    statuses = {r["status"] for r in report["records"]}
    if statuses & {"FAIL", "ERROR"}:
        return report, 1
    if not report["discovered_ids"] or statuses != {"PASS"}:
        return report, 3
    return report, 0


def main():
    # -I ignores PYTHONPATH; only the sealed profile source path is added.
    sys.path.insert(0, "/work/python/src")
    report, exit_code = run_suite("/work/python/tests", "/work/python")
    sys.stdout.write(json.dumps(report, ensure_ascii=True, separators=(",", ":")) + chr(10))
    sys.stdout.flush()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
