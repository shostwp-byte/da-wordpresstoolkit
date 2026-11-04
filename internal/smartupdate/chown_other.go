//go:build !linux

package smartupdate

func chownItem(_ string, _, _ uint32) error {
	return nil
}
