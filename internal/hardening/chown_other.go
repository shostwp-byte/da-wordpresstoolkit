//go:build !linux

package hardening

func chownNoFollow(_ string, _, _ uint32) error {
	return nil
}
