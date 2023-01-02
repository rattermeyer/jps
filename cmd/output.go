package cmd

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"time"
)

func createCsvFile(overallResult []JavaInfo) {
	filename := fmt.Sprintf("result_%v.csv", time.Now().Format(time.RFC3339))
	csvFile, err := os.Create(filename)
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}
	csvwriter := csv.NewWriter(csvFile)

	_ = csvwriter.Write([]string{"DetectionMethod", "ScanTimestamp", "Hostname", "Exe", "Username", "Vendor", "RuntimeName", "MajorVersion", "BuildNumber"})
	for _, infoRow := range overallResult {
		_ = csvwriter.Write([]string{
			infoRow.DetectionMethod.String(),
			infoRow.ScanTimestamp.Format(time.RFC3339),
			infoRow.Hostname,
			infoRow.Exe,
			infoRow.Username,
			infoRow.Vendor,
			infoRow.RuntimeName,
			strconv.Itoa(infoRow.MajorVersion),
			strconv.Itoa(infoRow.BuildNumber),
		})
	}
	csvwriter.Flush()
	err = csvFile.Close()
	if err != nil {
		log.Fatalf("failed closing file: %s", err)
	}

}
