package main

import (
	"testing"
)

func Test_extractMajorVersion(t *testing.T) {
	tests := []struct {
		name          string
		versionString string
		major         int
		build         int
	}{
		{"8", "1.8.0", 8, 0},
		{"8_202", "1.8.0_202", 8, 202},
		{"8_202-release", "1.8.0_202-release", 8, 202},
		{"11", "11.0.2", 11, 2},
		{"17", "17.0.5", 17, 5},
		{"6", "1.6.0_45-b06", 6, 45},
		{"5", "1.5.0_22-b03", 5, 22},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if major, build := extractMajorAndBuildNumber(tt.versionString); major != tt.major || build != tt.build {
				t.Errorf("extractMajorAndBuildNumber() = (%v, %v), major %v build %v", major, build, tt.major, tt.build)
			}

		})
	}
}

func Test_extractVersionString(t *testing.T) {
	tests := []struct {
		name        string
		versionLine string
		want        string
	}{
		{"1.6.0_45", "java version \"1.6.0_45\"", "1.6.0_45"},
		{"1.5.0_22", "java version \"1.5.0_22\"", "1.5.0_22"},
		{"11.0.3", "java version \"11.0.3\" 2019-04-16 LTS", "11.0.3"},
		{"openjdk 11.0.2", "openjdk version \"11.0.2\"", "11.0.2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractVersionString(tt.versionLine); got != tt.want {
				t.Errorf("extractVersionString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extractRuntimeName(t *testing.T) {
	type args struct {
		runtimeLine string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{"Java SE", args{runtimeLine: "Java(TM) SE Runtime Environment (build 1.6.0_45-b06)"}, "Java(TM) SE Runtime Environment"},
		{"Oracle OpenJDK", args{runtimeLine: "OpenJDK Runtime Environment 18.9 (build 11.0.2+9)"}, "OpenJDK Runtime Environment"},
		{"JetBrains s.r.o.", args{runtimeLine: "OpenJDK Runtime Environment JBR-17.0.5+1-653.14-jcef (build 17.0.5+1-b653.14)"}, "OpenJDK Runtime Environment JBR-"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractRuntimeName(tt.args.runtimeLine); got != tt.want {
				t.Errorf("extractRuntimeName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_requiresLicense(t *testing.T) {
	tests := []struct {
		name string
		jps  JavaProcessInfo
		want bool
	}{
		// TODO: Add test cases.
		{"OpenJDK 8 updated build", JavaProcessInfo{runtimeName: "OpenJDK Runtime Environment", majorVersion: 8, buildNumber: 212}, false},
		{"OpenJDK 11 build", JavaProcessInfo{runtimeName: "OpenJDK Runtime Environment", majorVersion: 11, buildNumber: 3}, false},
		{"Oracle JDK 8 latest free build", JavaProcessInfo{runtimeName: "Java(TM) SE Runtime Environment", majorVersion: 8, buildNumber: 202}, false},
		{"Oracle JDK 8 licensed build", JavaProcessInfo{runtimeName: "Java(TM) SE Runtime Environment", majorVersion: 8, buildNumber: 211}, true},
		{"Oracle JDK 11 build", JavaProcessInfo{runtimeName: "Java(TM) SE Runtime Environment", majorVersion: 11, buildNumber: 0}, true},
		{"Oracle JDK 12 build", JavaProcessInfo{runtimeName: "Java(TM) SE Runtime Environment", majorVersion: 12, buildNumber: 0}, false},
		{"Oracle JDK 17 build", JavaProcessInfo{runtimeName: "Java(TM) SE Runtime Environment", majorVersion: 17, buildNumber: 0}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requiresLicense(tt.jps); got != tt.want {
				t.Errorf("requiresLicense() = %v, want %v", got, tt.want)
			}
		})
	}
}
