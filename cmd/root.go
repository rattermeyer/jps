// Copyright © 2019 Richard Attermeyer <richard.attermeyer@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"

	"github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var log = logrus.New()
var findingsLog = logrus.New()

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "java-scanner",
	Short: "Java Scanner",
	Long:  `Java Scanner is a programm to detect java installations and running java processes.`,
	Run: func(cmd *cobra.Command, args []string) {
		Scan()
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "scan processes and report found java processes",
	Run: func(cmd *cobra.Command, args []string) {

		Scan()
	},
}

func formatMethodIfActivated(methodActivated bool, detectionMethod DetectionMethod) string {
	if methodActivated {
		return " " + detectionMethod.String()
	}
	return ""
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	findingsLog.SetFormatter(&logrus.JSONFormatter{})
	file, err := os.OpenFile("logrus.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err == nil {
		findingsLog.Out = file
	} else {
		log.Info("Failed to log to file, using default stderr")
	}
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.Version = "v0.0.1"
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.jps.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.

	scanCmd.Flags().BoolVarP(&detectWindowsRegistry, "scan-windows-registry", "r", false, "Activate windows registry scanning")
	scanCmd.Flags().BoolVarP(&detectLinuxAlternatives, "scan-linux-alternatives", "a", false, "Activate linux-alternatives scanning")
	scanCmd.Flags().BoolVarP(&detectRunningProcesses, "scan-running-processes", "p", false, "Activate running processes scanning")
	scanCmd.Flags().BoolVarP(&detectCurrentPath, "scan-current-path", "c", false, "Activate scanning of current path")

	scanCmd.Flags().BoolVarP(&detectFileSystemScan, "scan-file-system", "f", false, "Activate running processes scanning")

	defaultRootPaths := []string{"/usr/lib/jvm"}
	scanCmd.Flags().StringSliceVarP(&detectFileSystemScanRootPaths,
		"scan-file-system-root-paths",
		"R",
		defaultRootPaths,
		"A list of root paths, where the file system scan has to start")

	defaultExcludePaths := []string{}
	scanCmd.Flags().StringSliceVarP(&detectFileSystemScanExcludePaths,
		"scan-file-system-exclude-paths",
		"E",
		defaultExcludePaths,
		"A list of paths, that should be excluded from the search")
	scanCmd.Flags().BoolVarP(&appendToFindingsJson, "append-to-findings-json", "j", false, "append findings to findings.json file")

	rootCmd.AddCommand(scanCmd)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".jps" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".jps")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
