//go:build !linux

package clonesync

func chownNoFollow(_ string, _, _ uint32) error {
	return nil
}
