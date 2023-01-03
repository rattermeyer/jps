package cmd

import (
	"fmt"
	"strings"
	"time"
)

var detectWindowsRegistry bool
var detectLinuxAlternatives bool
var detectRunningProcesses bool
var detectFileSystemScan bool
var detectFileSystemScanRootPaths []string
var detectFileSystemScanExcludePaths []string

var detectCurrentPath bool
var appendToFindingsJson bool

type DetectionMethod int64

const (
	FileSystem DetectionMethod = iota
	LinuxAlternatives
	RunningProcesses
	WindowsRegistry
	CurrentPath
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
	case CurrentPath:
		return "current-path"
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
	ErrorText       string
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

	if detectWindowsRegistry {
		resultFileSystemScan := detectWindowsRegistryMain()
		overallResult = append(overallResult, resultFileSystemScan...)
		fmt.Println()
	}

	if detectCurrentPath {
		resultCurrentPath := detectCurrentPathMain()
		overallResult = append(overallResult, resultCurrentPath...)
		fmt.Println()
	}
	logOverallResults(overallResult)
	createCsvFile(overallResult)

	if appendToFindingsJson {
		addInfoToFindingsJson(overallResult)
	}

}

func isUnrecognizedOption(out []byte) bool {
	unrecognizedOption := false
	if len(out) > 0 {
		outLines := strings.Split(string(out), "\n")
		for _, line := range outLines {
			unrecognizedOption =
				unrecognizedOption || strings.Contains(line, "Unrecognized option: -XshowSettings:properties")
		}
	}
	return unrecognizedOption
}

func addErrorText(info *JavaInfo, err error, details string) {
	info.Valid = false

	errorSeparator := ""
	if info.ErrorText != "" {
		errorSeparator = "| "
	}
	detailsOutput := ""
	if details != "" {
		detailsOutput = " - details: " + strings.ReplaceAll(details, "\n", "")
	}
	info.ErrorText = info.ErrorText + errorSeparator + err.Error() + detailsOutput

}
