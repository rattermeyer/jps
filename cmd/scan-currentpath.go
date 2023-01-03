package cmd

import (
	"os"
	"os/exec"
	"time"
)

func detectCurrentPathMain() []JavaInfo {
	log.Infof("Starting detection '%s'...", CurrentPath)
	var result []JavaInfo

	path, err := exec.LookPath("java")
	if err != nil {
		log.Infoln("Could not find path")
		return result
	}

	info := JavaInfo{ScanTimestamp: time.Now(), DetectionMethod: CurrentPath}
	info.Hostname, _ = os.Hostname()
	info.Exe = path
	analyzeJavaBinaryMain(&info)
	result = append(result, info)
	log.Infof("Found java executable in current path: %v", path)
	return result

}
