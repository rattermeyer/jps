package cmd

import (
	ps "github.com/shirou/gopsutil/process"
	"os"
	"strings"
	"time"
)

func detectRunningProcessesMain() []JavaInfo {
	log.Infof("Starting detection '%s'...", RunningProcesses)
	resultRunningProcesses := extractJavaProcessInfos()
	log.Infof("number of detected running processes: %d!", len(resultRunningProcesses))

	return resultRunningProcesses
}

func extractJavaProcessInfos() []JavaInfo {
	processes, _ := ps.Processes()
	var result []JavaInfo
	// all findings in one scan should have the same timestamp
	// we get the timestamp once and add it to any info generated in this scan
	scanTimestamp := time.Now()

	for _, p1 := range processes {
		info := JavaInfo{ScanTimestamp: scanTimestamp, DetectionMethod: RunningProcesses}
		info.Hostname, _ = os.Hostname()
		name, _ := p1.Name()
		exe, _ := p1.Exe()
		info.Username, _ = p1.Username()
		if strings.EqualFold(name, "java") || strings.EqualFold(name, "java.exe") {
			if exe != "" {
				info.Exe = exe
				analyzeJavaBinaryMain(&info)
			}
			result = append(result, info)
		}

	}
	return result
}
