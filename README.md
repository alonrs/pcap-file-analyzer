# pcap-file-analyzer
Given a PCAP file with a trace of packets, this tool effectively assignes a unique integer for each unique 5-tuple header. The list of integers represent the packets' temporal locality and can be saved as a textual file. The tool can also be used to extract the inter-packet delay (in usec) and packet sizes (in bytes) from the PCAP file.
