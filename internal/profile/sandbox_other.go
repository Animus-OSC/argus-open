//go:build !linux

package profile

import "context"

// Unsupported hosts fail closed; there is no unsandboxed execution fallback.
func executeSandbox(context.Context, string) execution {
	return execution{ExitCode: -1}
}
