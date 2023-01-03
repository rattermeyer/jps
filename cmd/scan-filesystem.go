package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func detectFileSystemScanMain() []JavaInfo {
	log.Infof("Starting detection '%s' while excluding %s...\n", FileSystem, detectFileSystemScanExcludePaths)
	var result []JavaInfo
	scanTimestamp := time.Now()
	for _, rootPath := range detectFileSystemScanRootPaths {
		count := 0
		log.Infof("Scanning started at root path %s...\n", rootPath)

		targetFiles, _ := collectFiles(rootPath, detectFileSystemScanExcludePaths)

		log.Infof("File system scan found java installations: %v\n", targetFiles)
		for _, javaBinary := range targetFiles {
			info := JavaInfo{ScanTimestamp: scanTimestamp, DetectionMethod: FileSystem}
			info.Hostname, _ = os.Hostname()
			info.Exe = javaBinary
			analyzeJavaBinaryMain(&info)

			// include file in any case. info.valid will state if file is a valid java binary. info.
			result = append(result, info)
			if info.Valid {
				count = count + 1
			}
		}
		log.Infof("number of valid java installations found by filesystem scan below root path %s: %d!\n", rootPath, count)
	}
	return result
}

func collectFiles(dir string, excludeList []string) (fileList []string, err error) {
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if len(excludeList) > 0 && regexp.MustCompile(strings.Join(excludeList, "|")).Match([]byte(path)) {
			//fmt.Printf("%s\n", path)
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
