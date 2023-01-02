package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func detectFileSystemScanMain() []JavaInfo {
	fmt.Printf("Starting detection 'filesystem-scan' while excluding %s...\n", detectFileSystemScanExcludePaths)
	var result []JavaInfo
	scanTimestamp := time.Now()
	for _, rootPath := range detectFileSystemScanRootPaths {
		fmt.Printf("Scanning startet at root path %s...\n", rootPath)

		targetFiles, _ := collectFiles(rootPath, detectFileSystemScanExcludePaths)

		fmt.Printf("File system scan found java installations: %v\n", targetFiles)
		for _, javaBinary := range targetFiles {
			info := JavaInfo{ScanTimestamp: scanTimestamp, DetectionMethod: FileSystem}
			info.Hostname, _ = os.Hostname()
			info.Exe = javaBinary
			fetchProcessInfoMain(&info)
			result = append(result, info)
		}
		fmt.Printf("number of java installations found by filesystem scan below root path %s: %d!\n", rootPath, len(result))
	}
	return result
}

func collectFiles(dir string, excludeList []string) (fileList []string, err error) {
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if regexp.MustCompile(strings.Join(excludeList, "|")).Match([]byte(path)) {
			// fmt.Printf("%s\n", path)
			return nil
		}

		if info.IsDir() {
			return nil
		}
		file := filepath.Base(path)
		if strings.EqualFold(file, "java") || strings.EqualFold(file, "java.exe") {
			fileList = append(fileList, path)
		}

		return nil
	})
	if err != nil {
		log.Fatalf("walk error [%v]\n", err)
		return nil, err
	}
	return fileList, nil
}
