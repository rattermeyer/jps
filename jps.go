package main
import (
        "fmt"
        "os/exec"
        ps "github.com/shirou/gopsutil/process"
	"regexp"
	"strings"
)

func main() {
    p, _:= ps.Processes()

	for _, p1 := range p {
		name, _ := p1.Name()
		exe, _ := p1.Exe()
		username, _ := p1.Username()
		var vendor = ""
		var version = ""
		if strings.EqualFold(name, "java") {
			if exe != "" {
				out, err := exec.Command(exe, "-XshowSettings:properties", "-version").CombinedOutput()
				if err != nil {
					fmt.Println(err)
				} else {
					l := strings.Split(string(out), "\n")
					var validProperty = regexp.MustCompile("^(?P<Key>[a-z.]+) = (?P<Value>.+)$")
					for _, l1 := range l {
						line := strings.TrimSpace(l1)
						//fmt.Println(line)
						if validProperty.MatchString(line) {
							submatch := validProperty.FindStringSubmatch(line)
							key := submatch[1]
							value := submatch[2]
							switch key {
							case "java.vendor":
								vendor = value
							case "java.version":
								version = value
							}
						}
					}
					fmt.Println(fmt.Sprintf("%s|%s|%s|%s", exe, username, vendor, version))
				}
			}
		}
	}
}