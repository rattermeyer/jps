# Java Process Scanner

The Java Process Scanner scans for running java processes on the current host and prints out a JSON structure
with information about the used JRE/JDK.

The information helps to determine, if a license is required for the used version, due to the changed Oracle
license terms.


# compile

To compile, just execute

    go build .

## Running the scanner

### getting command line help
To get help, run the application via _go_:

    go run jps.go scan -h

Or run binary via:

    ./java-scanner scan --help

to print out the configuration options.

### searching running java processes
via:

    ./java-scanner scan -p

### searching via 'linux: alternatives list --java"
via

    ./java-scanner scan -a

### Searching in file system

Executing search in default file system root path below _/usr/lib/jvm_

    go run jps.go scan -f

Executing search in given file system root paths:

- by using flag _scan-file-system-root-paths_:


    go run jps.go scan -f --scan-file-system-root-paths "/home/vagrant/.sdkman,/usr/lib/jvm"

- or by using shorthand notation

    go run jps.go scan -f -R "/home/vagrant/.sdkman,/usr/lib/jvm"

Exclude directories from search

- by using flag _scan-file-system-exclude-paths_ / _-E_:


    go run jps.go scan -f -R "/home/vagrant/" -E /home/vagrant/.sdkman/,/home/vagrant/.jdks/

### Searching in windows registry
via

    go run jps.go scan -r

NOTE: searching in windows registry is yet not implemented!