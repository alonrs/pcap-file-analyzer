# Introduction

This tool analyzes [PCAP](https://en.wikipedia.org/wiki/Pcap) files. It extracts 5-tuples, inter-packet delays, and packet sizes from the given PCAP files, and saves them all in a textual formal that can be easily read and used in [packet classification benchmarks](https://alonrashelbach.com/2021/12/20/benchmarking-packet-classification-algorithms).

# Prerequisites
* A Linux operating system (also WSL)
* libpcap-dev (`sudo apt install libpcap-dev`)
* GNU Make, GCC, G++

* How to use
```bash
# Download submodules
./build.sh
# Compile
make
# Run with help message
./bin/util-pcap-analyzer.exe --help
```

# Others
If you happen to use this tool for an academic paper, please cite *Scaling Open vSwitch with a Computational Cache* (USENIX, NSDI 2022).

[MIT License](LICENSE).

Code contributions and bug fixes are welcome.
