package cmd

import (
	"os"
	"os/exec"
	"strings"
	"time"
)

func detectLinuxAlternativesMain() []JavaInfo {
	log.Infof("Starting detection '%s'...", LinuxAlternatives)
	//update-alternatives --list java
	cmdArgs := [4]string{"-n", "update-alternatives", "--list", "java"}

	var out []byte
	var err error

	command := exec.Command("sudo", cmdArgs[0:4]...)
	out, err = command.CombinedOutput()
	scanTimestamp := time.Now()

	var result []JavaInfo
	if err == nil && len(out) > 0 {

		splitFunction := func(c rune) bool {
			return c == '\n'
		}
		javaAlternatives := strings.FieldsFunc(string(out), splitFunction)
		log.Infof("detected java alternatives are: %q", javaAlternatives)

		for _, javaAlternative := range javaAlternatives {
			info := JavaInfo{ScanTimestamp: scanTimestamp, DetectionMethod: LinuxAlternatives}
			info.Hostname, _ = os.Hostname()
			info.Exe = javaAlternative
			analyzeJavaBinaryMain(&info)
			result = append(result, info)
		}
	} else {
		log.Infof("Found error: %s, out: %s", err.Error(), out)
	}
	log.Infof("number of detected java alternatives: %d!", len(result))
	return result
}
