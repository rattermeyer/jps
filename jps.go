package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	ps "github.com/shirou/gopsutil/process"
)

type JavaProcessInfo struct {
	hostname     string
	exe          string
	username     string
	vendor       string
	runtimeName  string
	majorVersion int
	buildNumber  int
}

func (jpi JavaProcessInfo) String() string {
	return fmt.Sprintf("{hostname: %s exe: %s user: %s vendor: %s runtime: %s major: %d build: %d may_require_license: %v}", jpi.hostname, jpi.exe, jpi.username, jpi.vendor, jpi.runtimeName, jpi.majorVersion, jpi.buildNumber, requiresLicense(jpi))
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
		} else {
			return v1, build
		}
	} else {
		return 0, 0
	}
}

func extractBuildNumber(candidate1 int, candidate2 int) int {
	if candidate2 != 0 {
		return candidate2
	} else {
		return candidate1
	}
}

func requiresLicense(jps JavaProcessInfo) bool {
	if strings.Contains(jps.runtimeName, "OpenJDK") {
		return false
	} else {
		if jps.majorVersion == 8 {
			if jps.buildNumber > 202 {
				return true
			} else {
				return false
			}
		}
		if (jps.majorVersion-11)%6 == 0 {
			return true
		} else {
			return false
		}
	}
}

func extractJavaProcessInfos(processes []*ps.Process) {
	for _, p1 := range processes {
		info := JavaProcessInfo{}
		info.hostname, _ = os.Hostname()
		name, _ := p1.Name()
		exe, _ := p1.Exe()
		info.username, _ = p1.Username()
		if strings.EqualFold(name, "java") {
			if exe != "" {
				out, err := fetchProcessInfo(&info, exe, false)
				if err != nil {
					out, err = fetchProcessInfo(&info, exe, true)
				}
				if err == nil && len(out) > 0 {
					l := strings.Split(string(out), "\n")
					extractProperties(l, &info)
					if info.vendor == "" {
						extractPropertiesFromVersionOutput(l, &info)
					}
				}
				if err != nil {
					// try without -XshowSettings:properties for java <= 1.6
					out, err = exec.Command(exe, "-version").CombinedOutput()
					l := strings.Split(string(out), "\n")
					extractPropertiesFromVersionOutput(l, &info)
					if err != nil {
						out, err = exec.Command(exe, "-version").CombinedOutput()
					}
				}
			}
			fmt.Println(info)
		}
	}
}

func extractPropertiesFromVersionOutput(versionOutput []string, info *JavaProcessInfo) {
	info.majorVersion, info.buildNumber = extractMajorAndBuildNumber(extractVersionString(versionOutput[0]))
	info.runtimeName = extractRuntimeName(versionOutput[1])
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
	} else {
		return ""
	}
}

func fetchProcessInfo(info *JavaProcessInfo, exe string, sudo bool) ([]byte, error) {
	info.exe = exe
	cmdArgs := [4]string{"-n", exe, "-XshowSettings:properties", "-version"}
	var out []byte
	var err error
	if sudo {
		command := exec.Command("sudo", cmdArgs[0:3]...)
		out, err = command.CombinedOutput()
	} else {
		command := exec.Command(exe, cmdArgs[2:4]...)
		out, err = command.CombinedOutput()
	}
	return out, err
}

func extractProperties(outputLine []string, info *JavaProcessInfo) {
	var validProperty = regexp.MustCompile("^(?P<Key>[a-z.]+) = (?P<Value>.+)$")
	for _, l1 := range outputLine {
		line := strings.TrimSpace(l1)
		if validProperty.MatchString(line) {
			submatch := validProperty.FindStringSubmatch(line)
			key := submatch[1]
			value := submatch[2]
			switch key {
			case "java.vendor":
				info.vendor = value
			case "java.version":
				info.majorVersion, info.buildNumber = extractMajorAndBuildNumber(value)
			case "java.runtime.name":
				info.runtimeName = value
			}
		}
	}
}

func main() {
	p, _ := ps.Processes()
	extractJavaProcessInfos(p)
}
