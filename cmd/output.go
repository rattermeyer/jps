package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"
)

func createCsvFile(overallResult []JavaInfo) {
	//timestampLayout := time.RFC3339
	timestampLayout := "2006-01-02_15-04-05"
	filename := fmt.Sprintf("result_%v.csv", time.Now().Format(timestampLayout))
	csvFile, err := os.Create(filename)
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}
	csvwriter := csv.NewWriter(csvFile)

	_ = csvwriter.Write([]string{"DetectionMethod", "ScanTimestamp", "Hostname", "Exe", "Valid", "Username", "Vendor", "RuntimeName", "MajorVersion", "BuildNumber", "Error Text"})
	for _, infoRow := range overallResult {
		_ = csvwriter.Write([]string{
			infoRow.DetectionMethod.String(),
			infoRow.ScanTimestamp.Format(timestampLayout),
			infoRow.Hostname,
			infoRow.Exe,
			strconv.FormatBool(infoRow.Valid),
			infoRow.Username,
			infoRow.Vendor,
			infoRow.RuntimeName,
			strconv.Itoa(infoRow.MajorVersion),
			strconv.Itoa(infoRow.BuildNumber),
			infoRow.ErrorText,
		})
	}
	csvwriter.Flush()
	err = csvFile.Close()
	if err != nil {
		log.Fatalf("failed closing file: %s", err)
	}

	log.Infof("Results are exported in CSV file '%s'", filename)

}

func addInfoToFindingsJson(infoList []JavaInfo) {
	var err error
	var findingsFile *os.File
	fileName := "findings.log"
	findingsFile, err = os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}

	for _, info := range infoList {
		infoAsJson, err := json.Marshal(info)
		if err != nil {
			log.Error(err)
		} else {
			if _, err = findingsFile.Write(infoAsJson); err != nil {
				panic(err)
			}
			_, _ = findingsFile.WriteString("\n")
		}
	}

	log.Infof("Wrote %d rows to findings file %s", len(infoList), fileName)
	err = findingsFile.Close()
	if err != nil {
		log.Errorln(err)
	}

}

func logOverallResults(overallResult []JavaInfo) {
	countValid := 0
	for _, javaInfo := range overallResult {
		if javaInfo.Valid {
			countValid++
		}
	}
	log.Infof("Overall-results: detected %d valid java installations!", countValid)
}
