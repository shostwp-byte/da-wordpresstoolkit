//go:build !linux

package webserver

func chownNoFollow(_ string, _, _ uint32) error {
	return nil
}
