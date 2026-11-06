// Package syntheticproject contains the only project used by the offline demo.
// The demo copies these files into an independent temporary Git repository.
package syntheticproject

import "embed"

//go:embed calculator.py tests/__init__.py tests/test_calculator.py
var Files embed.FS

// FailingCalculator is a second explicitly allowed fixture used to prove that
// a real nonzero test exit produces FAIL rather than a model-authored verdict.
const FailingCalculator = "def add(left, right):\n    return left - right\n"
