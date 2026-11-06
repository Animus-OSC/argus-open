package v1

import "errors"

var (
	ErrDuplicate   = errors.New("duplicate task or idempotency key")
	ErrUncertain   = errors.New("execution outcome requires reconciliation")
	ErrUnavailable = errors.New("required execution environment unavailable")
	ErrCapacity    = errors.New("local execution capacity unavailable")
	ErrNoTests     = errors.New("no tests were executed")
	ErrIncomplete  = errors.New("test execution was incomplete")
	ErrDenied      = errors.New("request denied")
)
