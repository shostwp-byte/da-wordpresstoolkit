//go:build !linux

package lifecycle

func chownIfRoot(_ string, _, _ uint32) {}
