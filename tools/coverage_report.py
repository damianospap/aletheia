#!/usr/bin/env python3
"""Line-coverage report using only the standard library (``trace``); no third-party coverage tool needed.

Usage:  python tools/coverage_report.py [--fail-under PERCENT]

The slow adversarial-input (ReDoS) tests are skipped here because tracing makes them very slow;
they run normally in the regular test suite.
"""
import argparse
import pathlib
import sys
import trace
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP = ("adversarial",)


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def run_tests():
    suite = unittest.TestLoader().discover(str(ROOT / "tests"))
    selected = unittest.TestSuite(t for t in flatten(suite) if not any(k in t.id() for k in SKIP))
    result = unittest.TextTestRunner(verbosity=0, stream=open("/dev/null", "w") if sys.platform != "win32" else sys.stderr).run(selected)
    return result.wasSuccessful()


def ranges(numbers):
    out, start, prev = [], None, None
    for n in sorted(numbers):
        if start is None:
            start = prev = n
        elif n == prev + 1:
            prev = n
        else:
            out.append((start, prev))
            start = prev = n
    if start is not None:
        out.append((start, prev))
    return ", ".join(f"{a}" if a == b else f"{a}-{b}" for a, b in out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fail-under", type=float, default=0.0)
    parser.add_argument("--show-missing", action="store_true")
    args = parser.parse_args()
    sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
    tracer = trace.Trace(count=True, trace=False, ignoredirs=[sys.prefix, sys.exec_prefix])
    ok = {}
    tracer.runctx("ok['passed'] = run_tests()", globals(), {"ok": ok, "run_tests": run_tests})
    counts = tracer.results().counts
    executed = {}
    for (filename, lineno), _ in counts.items():
        executed.setdefault(str(pathlib.Path(filename).resolve()), set()).add(lineno)
    total_exec = total_cov = 0
    print(f"{'module':<28}{'stmts':>7}{'cover':>8}")
    for path in sorted((ROOT / "src" / "aletheia").rglob("*.py")):
        exe = set(trace._find_executable_linenos(str(path)))
        if not exe:
            continue
        cov = exe & executed.get(str(path.resolve()), set())
        total_exec += len(exe)
        total_cov += len(cov)
        pct = 100.0 * len(cov) / len(exe)
        name = str(path.relative_to(ROOT / "src"))
        print(f"{name:<28}{len(exe):>7}{pct:>7.0f}%" + (f"   missing: {ranges(exe - cov)}" if args.show_missing and exe - cov else ""))
    overall = 100.0 * total_cov / total_exec
    print(f"{'TOTAL':<28}{total_exec:>7}{overall:>7.1f}%")
    if not ok.get("passed"):
        print("tests FAILED")
        return 1
    return 0 if overall >= args.fail_under else 2


if __name__ == "__main__":
    sys.exit(main())
