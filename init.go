package testns

import "os"

const reExecName = "docker-test-daemon-sandbox"
const dockerdBinary = "dockerd"

func init() {
	if os.Args[0] == reExecName {
		// SetNS()
		// Fork()
	}
}
