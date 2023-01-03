package cmd

import (
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

func analyzeJavaBinaryMain(info *JavaInfo) {
	info.Valid = true
	err := _analyzeJavaBinary(info, false)
	if err != nil {
		err = _analyzeJavaBinary(info, true)
		//note that errorText is already added to info.ErrorText
		log.Warnf("Failed to analyze java binary %s: %s", info.Exe, err.Error())

	}
}

func _analyzeJavaBinary(info *JavaInfo, sudo bool) error {
	cmdArgs := [4]string{"-n", info.Exe, "-XshowSettings:properties", "-version"}
	var out []byte
	var err error
	if sudo {
		command := exec.Command("sudo", cmdArgs[0:3]...)
		out, err = command.CombinedOutput()
	} else {
		command := exec.Command(info.Exe, cmdArgs[2:4]...)
		out, err = command.CombinedOutput()
	}
	if err == nil {
		if len(out) > 0 {
			l := strings.Split(string(out), "\n")
			extractProperties(l, info)
		}
		return nil
	}

	//err != nil

	unrecognizedOption := isUnrecognizedOption(out)
	if unrecognizedOption {
		// try without -XshowSettings:properties for java <= 1.6
		return extractPropertiesFromVersionOutput(info)
	} else {
		addErrorText(info, err, string(out))

		return err
	}
}

func extractBuildNumber(candidate1 int, candidate2 int) int {
	if candidate2 != 0 {
		return candidate2
	}
	return candidate1
}

func extractPropertiesFromVersionOutput(info *JavaInfo) error {

	var err error
	err = nil
	out, err := exec.Command(info.Exe, "-version").CombinedOutput()
	if err != nil {
		log.Warnf("extractPropertiesFromVersionOutput exe:%s, error:%s", info.Exe, err)
		addErrorText(info, err, string(out))
		return err
	}
	versionOutput := strings.Split(string(out), "\n")
	info.MajorVersion, info.BuildNumber = extractMajorAndBuildNumber(extractVersionString(versionOutput[0]))
	info.RuntimeName = extractRuntimeName(versionOutput[1])
	return nil
}

func extractMajorAndBuildNumber(versionString string) (int, int) {
	major, _ := regexp.Compile(`(\d+)\.(\d).(\d).*?_?(\d+)?`)
	versionFormat := major.MatchString(versionString)
	if versionFormat {
		allString := major.FindStringSubmatch(versionString)
		v1, _ := strconv.Atoi(allString[1])
		v2, _ := strconv.Atoi(allString[2])
		v3, _ := strconv.Atoi(allString[3])
		v4, _ := strconv.Atoi(allString[4])
		build := extractBuildNumber(v3, v4)
		if v1 == 1 {
			return v2, build
		}
		return v1, build
	}
	return 0, 0

}

func extractRuntimeName(runtimeLine string) string {
	pattern, _ := regexp.Compile(`(\D+).*\(.*?\)`)
	runtimeName := pattern.FindStringSubmatch(runtimeLine)[1]
	return strings.Trim(runtimeName, " ")
}

func extractVersionString(versionLine string) string {
	versionStringMatch, _ := regexp.Compile(".*? version \"(.*?)\"")

	versionFormat := versionStringMatch.MatchString(versionLine)
	if versionFormat {
		allMatch := versionStringMatch.FindStringSubmatch(versionLine)
		return allMatch[1]
	}
	return ""

}

func extractProperties(outputLine []string, info *JavaInfo) {
	var validProperty = regexp.MustCompile("^(?P<Key>[a-z.]+) = (?P<Value>.+)$")
	for _, l1 := range outputLine {
		line := strings.TrimSpace(l1)
		if validProperty.MatchString(line) {
			submatch := validProperty.FindStringSubmatch(line)
			key := submatch[1]
			value := submatch[2]
			switch key {
			case "java.vendor":
				info.Vendor = value
			case "java.version":
				info.MajorVersion, info.BuildNumber = extractMajorAndBuildNumber(value)
			case "java.runtime.name":
				info.RuntimeName = value
			}
		}
	}
}
