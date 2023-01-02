package cmd

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var detectWindowsRegistry bool
var detectLinuxAlternatives bool
var detectRunningProcesses bool
var detectFileSystemScan bool
var detectFileSystemScanRootPaths []string
var detectFileSystemScanExcludePaths []string

var appendToFindingsJson bool

type DetectionMethod int64

const (
	FileSystem DetectionMethod = iota
	LinuxAlternatives
	RunningProcesses
	WindowsRegistry
)

func (s DetectionMethod) String() string {
	switch s {
	case FileSystem:
		return "file-system"
	case LinuxAlternatives:
		return "linux-alternatives"
	case RunningProcesses:
		return "running-processes"
	case WindowsRegistry:
		return "windows-registry"
	}
	return "unknown"
}

type JavaInfo struct {
	DetectionMethod DetectionMethod
	ScanTimestamp   time.Time
	Hostname        string
	Exe             string
	Valid           bool
	Username        string
	Vendor          string
	RuntimeName     string
	MajorVersion    int
	BuildNumber     int
	RequiresLicense bool
	ErrorText       string
}

func extractMajorAndBuildNumber(versionString string) (int, int) {
	major, _ := regexp.Compile("(\\d+)\\.(\\d).(\\d).*?_?(\\d+)?")
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

func extractBuildNumber(candidate1 int, candidate2 int) int {
	if candidate2 != 0 {
		return candidate2
	}
	return candidate1
}

func requiresLicense(jps *JavaInfo) bool {
	if strings.Contains(jps.RuntimeName, "OpenJDK") {
		return false
	}
	if jps.MajorVersion == 8 {
		if jps.BuildNumber > 202 {
			return true
		}
		return false

	}
	if (jps.MajorVersion-11)%6 == 0 {
		return true
	}
	return false

}

func fetchProcessInfoMain(info *JavaInfo) error {
	info.Valid = true
	out, err := fetchProcessInfo(info, false)
	if err != nil {
		out, err = fetchProcessInfo(info, true)
	}
	if err == nil {
		if len(out) > 0 {
			l := strings.Split(string(out), "\n")
			extractProperties(l, info)
			if info.Vendor == "" {
				extractPropertiesFromVersionOutput(info)
			}
		}
	} else {
		// try without -XshowSettings:properties for java <= 1.6
		err2 := extractPropertiesFromVersionOutput(info)
		if err2 != nil {
			return err2
		}
		return err
	}

	info.RequiresLicense = requiresLicense(info)
	return nil

}

func extractPropertiesFromVersionOutput(info *JavaInfo) error {

	var err error
	err = nil
	out, err := exec.Command(info.Exe, "-version").CombinedOutput()
	if err != nil {
		log.Warnf("extractPropertiesFromVersionOutput exe:%s, error:%s", info.Exe, err)
		info.Valid = false
		info.ErrorText = err.Error()
		return err
	}
	versionOutput := strings.Split(string(out), "\n")
	info.MajorVersion, info.BuildNumber = extractMajorAndBuildNumber(extractVersionString(versionOutput[0]))
	info.RuntimeName = extractRuntimeName(versionOutput[1])
	return nil
}

func extractRuntimeName(runtimeLine string) string {
	pattern, _ := regexp.Compile("(\\D+).*\\(.*?\\)")
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

func fetchProcessInfo(info *JavaInfo, sudo bool) ([]byte, error) {
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
	return out, err
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

func Scan() {

	overallResult := []JavaInfo{}

	if detectRunningProcesses {
		resultRunningProcesses := detectRunningProcessesMain()
		overallResult = append(overallResult, resultRunningProcesses...)
		fmt.Println()
	}
	if detectLinuxAlternatives {
		resultLinuxAlternatives := detectLinuxAlternativesMain()
		overallResult = append(overallResult, resultLinuxAlternatives...)
		fmt.Println()
	}
	if detectFileSystemScan {
		resultFileSystemScan := detectFileSystemScanMain()
		overallResult = append(overallResult, resultFileSystemScan...)
		fmt.Println()
	}

	printNoYetImplemented(detectWindowsRegistry, "detect-windows-registry")

	logOverallResults(overallResult)
	createCsvFile(overallResult)

	if appendToFindingsJson {
		addInfoToFindingsJson(overallResult)
	}

}

func printNoYetImplemented(detectMethod bool, detectMethodName string) {
	if detectMethod {
		log.Warnf("Starting %v ... is not yet implemented!\n", detectMethodName)
		fmt.Println()
	}
}
