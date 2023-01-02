# Java Process Scanner

The Java Process Scanner scans for running java processes on the current host and prints out a JSON structure
with information about the used JRE/JDK.

The information helps to determine, if a license is required for the used version, due to the changed Oracle
license terms.


## Running the scanner

To get help, run the application via

    go run jps.go scan -h

to print out the configuration options.


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