//go:build !linux

package quicktools

func chownNoFollow(_ string, _, _ uint32) error {
	return nil
}
