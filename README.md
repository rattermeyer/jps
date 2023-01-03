# Java Scanner

The Java Scanner scans for java installations and running java processes on the current 
host and creates a csv file with information about the JRE/JDK instances, that have been found.

The information helps to determine, if a license is required for the used version, due to the changed Oracle
license terms.

The java scanner is implemented in golang.


# compile

To compile, just execute

    go build .

## Running the scanner

### getting command line help
To get help, run the application via _go_:

    ./java-scanner scan -h

Or run binary via:

    ./java-scanner scan --help

to print out the configuration options:

```
scan processes and report found java processes

Usage:
  java-scanner scan [flags]

Flags:
  -j, --append-to-findings-json                  append findings to findings.json file
  -h, --help                                     help for scan
  -c, --scan-current-path                        Activate scanning of current path
  -f, --scan-file-system                         Activate running processes scanning
  -E, --scan-file-system-exclude-paths strings   A list of paths, that should be excluded from the search
  -R, --scan-file-system-root-paths strings      A list of root paths, where the file system scan has to start (default [/usr/lib/jvm])
  -a, --scan-linux-alternatives                  Activate linux-alternatives scanning
  -p, --scan-running-processes                   Activate running processes scanning
  -r, --scan-windows-registry                    Activate windows registry scanning

```

### searching running java processes
via:

    ./java-scanner scan -p

### searching via 'linux: alternatives list --java"
via

    ./java-scanner scan -a

### Searching in file system

**Executing search in default file system root path below _/usr/lib/jvm_**

    ./java-scanner scan -f

**Executing search in given file system root paths:**

By using flag _scan-file-system-root-paths_:

    ./java-scanner scan -f --scan-file-system-root-paths "/home/vagrant/.sdkman,/usr/lib/jvm"

Or by using shorthand notation:

    ./java-scanner scan -f -R "/home/vagrant/.sdkman,/usr/lib/jvm"

**Exclude directories from search**

By using flag _scan-file-system-exclude-paths_ / _-E_:

    ./java-scanner scan -f -R "/home/vagrant/" -E /home/vagrant/.sdkman/,/home/vagrant/.jdks/

### Searching in windows registry
via

    ./java-scanner scan -r

NOTE: searching in windows registry is yet not implemented!