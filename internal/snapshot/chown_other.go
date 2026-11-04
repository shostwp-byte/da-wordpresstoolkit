//go:build !linux

package snapshot

func chownNoFollow(_ string, _, _ uint32) error {
	return nil
}
