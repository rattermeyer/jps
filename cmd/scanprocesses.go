package cmd

import (
	"fmt"
	ps "github.com/shirou/gopsutil/process"
	"os"
	"strings"
	"time"
)

func detectRunningProcessesMain() []JavaInfo {
	fmt.Printf("Starting process detection...\n")
	p, _ := ps.Processes()
	resultRunningProcesses := extractJavaProcessInfos(p)
	fmt.Printf("detected %d running processes!\n", len(resultRunningProcesses))

	return resultRunningProcesses
}

func extractJavaProcessInfos(processes []*ps.Process) []JavaInfo {
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
				fetchProcessInfoMain(&info)
			}
			result = append(result, info)
		}

	}
	return result
}
