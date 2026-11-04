//go:build !linux

package extensions

func chownFile(_ string, _, _ uint32) error {
	return nil
}
