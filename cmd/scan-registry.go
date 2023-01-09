//go:build !windows
// +build !windows

package cmd

func detectWindowsRegistryMain() []JavaInfo {
	log.Warnf("Not starting detection '%s', since this is only implemented for windows!", WindowsRegistry)
	var result []JavaInfo
	//scanTimestamp := time.Now()
	return result
}
