#ifndef PCAPUTILS_H
#define PCAPUTILS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <pcap/pcap.h>

#include <stdio.h>

#include <vector>
#include <list>
#include <utility>
#include <map>
#include <string>
#include <sstream>

#include "log.h"
#include "errorf.h"
#include "net-checksums.h"

const int WORD_WIDTH = 4;

const int PROTOCOL_TCP = 6;
const int PROTOCOL_UDP = 17;
const int PROTOCOL_ICMP = 1;

const int HEADER_SIZE_IPv4 = 20;
const int HEADER_SIZE_TCP = 20;
const int HEADER_SIZE_UDP = 8;
const int HEADER_SIZE_ICMP = 8;

// We use 5-tuple packets
using packet_header = std::array<uint32_t, 5>;

struct TracePacket {
    packet_header header; /* The 5-tuple of the packet           */
    long priority;        /* The matching rule's unique priority */
    long size;            /* The size of this, in bytes          */
    long timestamp;       /* The packet timestamp                */
};

/**
 * @brief Writes packets to PCAP files. Packets have 5-tuple structure
 * and their playload indiates the rule number they should match.
 */
class PcapWriter {

    pcap_dumper_t* pcap_dumper;
    u_char* buffer;

    /**
     * @brief Writes the content of a packet to "buffer"
     * @param packet Information on the packet to generate
     * @param buffer Location in memory to write the packet
     * @returns The nubmer of bytes written to buffer
     */
    uint32_t generate_packet(TracePacket pkt_info, u_char* buffer) {

        // TCP packet size: 58 bytes
        // UDP packet size: 46 bytes
        // ICMP packet size: 46 bytes

        // Ethernet header. Source & destination MACs are 0,
        // Ethernet protocol is IP
        struct ether_header ether_hdr = {0};
        ether_hdr.ether_type = htons(ETHERTYPE_IP);

        uint32_t out_length = 0;
        memcpy(buffer+out_length, &ether_hdr, sizeof(struct ether_header));
        out_length += sizeof(struct ether_header);


        // TCP/UDP heder length
        uint16_t l4_header_len = (pkt_info.header[0] == PROTOCOL_TCP) ? HEADER_SIZE_TCP :
                                 (pkt_info.header[0] == PROTOCOL_UDP) ? HEADER_SIZE_UDP :
                                 (pkt_info.header[0] == PROTOCOL_ICMP) ? HEADER_SIZE_ICMP :
                                         0;

        // Calculate payload
        int payload_size = pkt_info.size - HEADER_SIZE_IPv4 - l4_header_len;
        /* The payload has at least 4 byes of data */
        if (payload_size <= 4) {
            payload_size = 4;
            pkt_info.size = payload_size + HEADER_SIZE_IPv4 + l4_header_len;
        }

        // IP header
        static_assert(sizeof(struct iphdr)==HEADER_SIZE_IPv4, "Static sizes error in pcap_utils");
        struct iphdr iphdr;
        iphdr.version = 4; // For IPv4 it is always 4
        iphdr.ihl = HEADER_SIZE_IPv4 / WORD_WIDTH; // 20 Bytes of header
        iphdr.tos = 0; // DSCP: 0 (best effort), ECN:0 (not using ECN)
        iphdr.tot_len = htons(pkt_info.size); // Packet size
        iphdr.id = htons(1); // Packet is not fragmented; ID has no meaningful value (RFC6864, sec 4.1)
        iphdr.frag_off = 0; // Flags: don't fragment. Always first packet
        iphdr.ttl = 2; // Two hops
        iphdr.protocol = pkt_info.header[0];
        iphdr.check = 0; // Will be calculated next

        // Source and destination IP addresses
        iphdr.saddr = htonl(pkt_info.header[1]);
        iphdr.daddr = htonl(pkt_info.header[2]);

        // Calculate IP header checksum
        compute_ip_checksum(&iphdr);

        memcpy(buffer+out_length, &iphdr, sizeof(iphdr));
        out_length += sizeof(iphdr);

        unsigned short * ippayload = (unsigned short *)(buffer+out_length);

        // In case of TCP header
        if (pkt_info.header[0] == PROTOCOL_TCP) {
            static_assert(sizeof(struct tcphdr)==HEADER_SIZE_TCP, "Static sizes error in pcap_utils");
            struct tcphdr tcphdr;
            tcphdr.th_sport = htons(pkt_info.header[3]); // Source port
            tcphdr.th_dport = htons(pkt_info.header[4]); // Dest port
            tcphdr.th_seq = 0; // No sequence number
            tcphdr.th_ack = 0; // No ack number
            tcphdr.th_off = HEADER_SIZE_TCP / WORD_WIDTH; // 20 Bytes header size
            tcphdr.th_x2 = 0; // Reserved
            tcphdr.th_flags = TH_SYN; // Flag is always syn connection
            tcphdr.th_win = htons(8192); // Window size standard
            tcphdr.th_urp = 0; // No urgent number

            memcpy(buffer+out_length, &tcphdr, HEADER_SIZE_TCP);
            out_length += HEADER_SIZE_TCP;
        }
        // In case of UDP header
        else if (pkt_info.header[0] == PROTOCOL_UDP) {
            static_assert(sizeof(struct udphdr)==HEADER_SIZE_UDP, "Static sizes error in pcap_utils");
            struct udphdr udphdr;
            udphdr.uh_sport = htons(pkt_info.header[3]); // Source port
            udphdr.uh_dport = htons(pkt_info.header[4]); // Dest port
            udphdr.uh_ulen = htons(HEADER_SIZE_UDP+payload_size); // Header + pyload
            udphdr.uh_sum = 0; // Checksum is optional

            memcpy(buffer+out_length, &udphdr, HEADER_SIZE_UDP);
            out_length += HEADER_SIZE_UDP;
        }
        // In case of ICMP
        else if (pkt_info.header[0] == PROTOCOL_ICMP) {
            static_assert(sizeof(struct icmp6_hdr)==HEADER_SIZE_ICMP, "Static sizes error in pcap_utils");
            struct icmp6_hdr icmp6hdr;
            icmp6hdr.icmp6_type = 8; // Echo (ping)
            icmp6hdr.icmp6_code = 0; // N/A
            icmp6hdr.icmp6_cksum = 0; // Calculated later
            icmp6hdr.icmp6_dataun.icmp6_un_data32[0] = 0; // Identifier, Seq number: 0

            memcpy(buffer+out_length, &icmp6hdr, HEADER_SIZE_ICMP);
            out_length += HEADER_SIZE_ICMP;
        }
        // Not supported
        else {
            throw errorf("IP protocol not supported. Got %d", pkt_info.header[0]);
        }

        // Create the payload (big-endien 32bit integer)
        uint32_t payload = htonl(pkt_info.priority);
        memcpy(buffer+out_length, &payload, 4);
        out_length += sizeof(uint32_t);
        payload_size -= sizeof(uint32_t);

        // Pad with zeros to the payload size
        memset(buffer+out_length, 0, payload_size);
        out_length += payload_size;

        // Calculate L4 checksum (with payload)
        if (pkt_info.header[0] == PROTOCOL_TCP) {
            compute_tcp_checksum(&iphdr, ippayload);
        } else if (pkt_info.header[0] == PROTOCOL_UDP) {
            compute_udp_checksum(&iphdr, ippayload);
        } else if (pkt_info.header[0] == PROTOCOL_ICMP) {
            compute_icmp_checksum(&iphdr, ippayload);
        }

        return out_length;
    }

public:

    /* Open PCAP for writing */
    PcapWriter(const char* filename) {
        // Initiate a dummy PCAP handle
        pcap_t* p = pcap_open_dead(1, 65535);
        // Open a file for writing
        this->pcap_dumper = pcap_dump_open(p, filename);
        if (!pcap_dumper) {
            throw errorf("Cannot open pcap for writing!");
        }
        buffer = new u_char[8192];
    }

    /* Close the PCAP file */
    ~PcapWriter() {
        // Close dumper
        pcap_dump_close(pcap_dumper);
        delete[] buffer;
    }

    /* Appends "packet" to PCAP in "filename" */
    void append_packet(TracePacket& packet) {

        // Generate the packet
        uint32_t n = generate_packet(packet, buffer);

        // Generate libcap packet header
        struct pcap_pkthdr h = {0};
        h.caplen = n;
        h.len = n;
        h.ts.tv_sec = (packet.timestamp / 1000000);
        h.ts.tv_usec = (packet.timestamp % 1000000);

        // Write to PCAP file
        pcap_dump((u_char*)pcap_dumper, &h, buffer);
    }
};


/**
 * @brief Reads PCAP files
 */
class PcapReader {

    /**
     * @brief 5-tuple packet header
     */
    struct five_tuple_header {
        int protocol;
        struct in_addr ip_src;
        struct in_addr ip_dst;
        int port_src;
        int port_dst;

        // Required for std::map
        bool operator<(const five_tuple_header& other) const {
            return
                (protocol < other.protocol) ||
                (ip_src.s_addr < other.ip_src.s_addr) ||
                (ip_dst.s_addr < other.ip_dst.s_addr) ||
                (port_src < other.port_src) ||
                (port_dst < other.port_dst);
        }

        std::string to_string() const {
            std::stringstream ss;
            std::string src_ip_str(inet_ntoa(ip_src));
            std::string dst_ip_str(inet_ntoa(ip_dst));
            ss << "proto:" << protocol << " "
               << "ip-src:" << src_ip_str.c_str() << " "
               << "ip-dst:" << dst_ip_str.c_str() << " "
               << "port-src:" << ntohs(port_src) << " "
               << "port-dst:" << ntohs(port_dst);
            return ss.str();
        }
    };

    std::vector<packet_header> pcap_packets;
    std::vector<long> locality;
    std::vector<long> pkt_size;
    std::vector<long> pkt_times;
    std::map<std::string, int> seen_headers;

    /**
     * @brief libpcap callback for reading packet
     * @param user Pointer to instance
     * @param h The packet header information
     * @param bytes The packet bytes
     */
    static void pcap_handler (u_char* user,
                              const struct pcap_pkthdr* h,
                              const u_char* bytes) {

        // Get the output vector from context
        PcapReader& instance = *(PcapReader*)(user);

        // Note: since we used Ethernet protocol filter,
        // "bytes" points directly on the IP header.
        const struct ip* iphdr = (const struct ip*)(bytes);

        // Build the 5-tuple header
        five_tuple_header fthdr;
        fthdr.protocol = iphdr->ip_p;
        fthdr.ip_src = iphdr->ip_src;
        fthdr.ip_dst = iphdr->ip_dst;

        // What is the ip protocol? (we support TCP, UDP, ICMP)
        // TCP
        if (iphdr->ip_p == 6) {
            const struct tcphdr* tcphdr = (const struct tcphdr*)(bytes + 20);
            fthdr.port_src = tcphdr->th_sport;
            fthdr.port_dst = tcphdr->th_dport;
        }
        // UDP
        else if (iphdr->ip_p == 17) {
            const struct udphdr* udphdr = (const struct udphdr*)(bytes + 20);
            fthdr.port_src = udphdr->uh_sport;
            fthdr.port_dst = udphdr->uh_dport;
        }
        // All other
        else {
            fthdr.port_src = 0;
            fthdr.port_dst = 0;
        }

        std::string repr = fthdr.to_string();
        auto it = instance.seen_headers.find(repr);
        size_t value;

        // For debug
        // NM_MESSAGE("%s", repr);

        // In case the packet is new
        if (it == instance.seen_headers.end()) {
            value = instance.seen_headers.size();
            instance.seen_headers[repr] = value;
        }
        // In case the packet is not new
        else {
            value = it->second;
        }

        // Update vectors
        instance.locality.push_back(value);
        instance.pkt_size.push_back(h->len);
        instance.pkt_times.push_back(h->ts.tv_sec * 1e6 + h->ts.tv_usec);

        packet_header packet;
        packet[0] = fthdr.protocol;
        packet[1] = ntohl(fthdr.ip_src.s_addr);
        packet[2] = ntohl(fthdr.ip_dst.s_addr);
        packet[3] = ntohs(fthdr.port_src);
        packet[4] = ntohs(fthdr.port_dst);
        instance.pcap_packets.push_back(packet);
    }

public:

    void read(const char* filename, int count) {

        char error[PCAP_ERRBUF_SIZE];

        // Open PCAP file for reading
        pcap_t* p = pcap_open_offline(filename, error);
        if (p == NULL) {
            throw errorf("PCAP error: %s", error);
        }

        // Compile IPV4 filter
        struct bpf_program filter;
        if (PCAP_ERROR == pcap_compile(p, &filter, "ip", 1, 0)) {
            pcap_close(p);
            throw errorf("pcap_compile error: %s", pcap_geterr(p));
        }

        // Set the filter
        if (PCAP_ERROR == pcap_setfilter(p, &filter)) {
            pcap_close(p);
            throw errorf("pcap_setfilter error: %s", pcap_geterr(p));
        }

        // Process "count" packets with PCAP
        if (PCAP_ERROR == pcap_dispatch(p, count, pcap_handler, (u_char*)this)) {
            pcap_close(p);
            throw errorf("pcap_dispatch error: %s", pcap_geterr(p));
        }

        // Close PCAP file
        pcap_close(p);
    }

    /**
     * @brief Returns the locality of this
     */
    const std::vector<long>& get_locality() const {
        return locality;
    }

    /**
     * @brief Returns the sizes of packets in this
     * @return
     */
    const std::vector<long>& get_sizes() const {
        return pkt_size;
    }

    /**
     * @brief Returns the timestampts of packets in this
     * @return
     */
    const std::vector<long>& get_timestamps() const {
        return pkt_times;
    }
};
#endif
