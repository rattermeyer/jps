//go:build windows

package cmd

import (
	"errors"
	"golang.org/x/sys/windows/registry"
	"os"
	"syscall"
	"time"
)

func detectWindowsRegistryMain() []JavaInfo {
	log.Infof("Starting detection '%s'...", WindowsRegistry)
	var result []JavaInfo
	scanTimestamp := time.Now()

	path := `SOFTWARE\JavaSoft`

	javaBinaries := removeDuplicateValues(iterate(path))

	for _, javaBinary := range javaBinaries {
		info := JavaInfo{ScanTimestamp: scanTimestamp, DetectionMethod: WindowsRegistry}
		info.Hostname, _ = os.Hostname()
		info.Exe = javaBinary
		analyzeJavaBinaryMain(&info)
		result = append(result, info)
	}

	log.Infof("Found %d java binaries: %s", len(result), result)

	return result
}

func removeDuplicateValues(intSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}

	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func iterate(path string) []string {
	log.Infof("Start iterating in path: %s", path)
	result := []string{}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS)
	defer k.Close()
	if err != nil {
		log.Warnf("Error when reading path %s: %s", path, err.Error())
		return []string{}
	}

	javaHomeValue := readJavaHome(path)
	if javaHomeValue != "" {
		result = append(result, javaHomeValue)
	}

	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		log.Warnf("Error when reading subkeynames of path %s: %s", path, err.Error())
	} else {
		for _, name := range names {
			//log.Infof("Found subkey from path %s with name %s", path, name)
			resultsFromSubelemets := iterate(path + "\\" + name)
			result = append(result, resultsFromSubelemets...)
		}
	}

	return result
}

func readJavaHome(path string) string {
	keyForQueryValue, errForQueryValue := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	defer keyForQueryValue.Close()
	if errForQueryValue != nil {
		log.Warnf("Cannot open path '%s' for query values! Error: %s", path, errForQueryValue.Error())
		return ""
	}
	javaHomeValue, _, errorReadJavaHome := keyForQueryValue.GetStringValue("JavaHome")
	if errorReadJavaHome != nil {
		if !errors.Is(errorReadJavaHome, syscall.ERROR_FILE_NOT_FOUND) {
			log.Warnf("cannot read JavaHome value in path %s, error: %s", path, errorReadJavaHome.Error())
		}
		return ""
	} else {
		return javaHomeValue + "\\bin\\java.exe"
	}

}
