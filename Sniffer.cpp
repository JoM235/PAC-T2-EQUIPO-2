// Integrante 2: Jonathan Emir Jacobo Martinez
#include "Sniffer.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <algorithm>

struct CapturaData {
    std::function<void(std::shared_ptr<Evento>)> cb;
    std::atomic<bool>* running;
};

SnifferMonitor::SnifferMonitor(const std::string& iface, const std::string& ip) 
    : interfaz(iface), ip_local(ip), handle(nullptr) {
    handle = pcap_open_live(iface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        throw std::runtime_error("Error al abrir interfaz: " + std::string(errbuf));
    }
    
    struct bpf_program fp;
    std::string filter_exp = "host " + ip_local + " and (arp or icmp or tcp or udp)";
    
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        pcap_close(handle);
        throw std::runtime_error("Error al compilar filtro BPF");
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        pcap_freecode(&fp);
        pcap_close(handle);
        throw std::runtime_error("Error al aplicar filtro");
    }
    pcap_freecode(&fp);
    std::cout << "[Sniffer] Capturando en " << iface << " (Filtro: " << filter_exp << ")" << std::endl;
}

SnifferMonitor::~SnifferMonitor() {
    if (handle) pcap_close(handle);
}

void SnifferMonitor::iniciarCaptura(std::function<void(std::shared_ptr<Evento>)> callback, std::atomic<bool>& ejecutar) {
    CapturaData data{callback, &ejecutar};
    while (ejecutar) {
        int result = pcap_dispatch(handle, 1, packetHandler, (u_char*)&data);
        if (result == -1) {
            std::cerr << "[Sniffer] Error en captura" << std::endl;
            break;
        }
    }
}

void SnifferMonitor::packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    auto* data = reinterpret_cast<CapturaData*>(userData);
    if (!data->running->load()) return;
    
    struct ether_header* eth_header = (struct ether_header*)packet;
    std::shared_ptr<PaqueteEvento> evento;
    
    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        evento = std::make_shared<ARPEvento>(packet, pkthdr->len);
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
        if (ip_header->ip_p == IPPROTO_ICMP) {
            evento = std::make_shared<ICMPEvento>(packet, pkthdr->len);
        } else if (ip_header->ip_p == IPPROTO_TCP) {
            evento = std::make_shared<TCPEvento>(packet, pkthdr->len);
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            evento = std::make_shared<UDPEvento>(packet, pkthdr->len);
        }
    }
    if (evento) data->cb(evento);
}

PaqueteEvento::PaqueteEvento(const std::string& tipo_paquete, const u_char* packet, int len) {
    tipo = tipo_paquete;
    timestamp = std::chrono::system_clock::now();
    int bytes_to_save = std::min(len, 24);
    header_bytes.assign(packet, packet + bytes_to_save);
}

std::string PaqueteEvento::bytesToHex(int max_bytes) const {
    std::stringstream ss;
    int count = std::min(max_bytes, (int)header_bytes.size());
    for (int i = 0; i < count; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)header_bytes[i];
        if (i < count - 1) ss << " ";
    }
    return ss.str();
}

ARPEvento::ARPEvento(const u_char* packet, int len) : PaqueteEvento("arp", packet, len) {
    struct ether_arp* arp = (struct ether_arp*)(packet + sizeof(struct ether_header));
    src_ip = std::to_string(arp->arp_spa[0]) + "." + std::to_string(arp->arp_spa[1]) + "." +
             std::to_string(arp->arp_spa[2]) + "." + std::to_string(arp->arp_spa[3]);
}

nlohmann::json ARPEvento::toJSON() const {
    return {{"event", "arp_packet"}, {"source_ip", src_ip}, {"header_bytes", bytesToHex()}, {"timestamp", getTimestampStr()}};
}

void ARPEvento::imprimirResumen() const {
    std::cout << "[PAQUETE] ARP desde " << src_ip << " [" << getTimestampStr() << "]" << std::endl;
}

ICMPEvento::ICMPEvento(const u_char* packet, int len) : PaqueteEvento("icmp", packet, len) {}

nlohmann::json ICMPEvento::toJSON() const {
    return {{"event", "icmp_packet"}, {"header_bytes", bytesToHex()}, {"timestamp", getTimestampStr()}};
}

void ICMPEvento::imprimirResumen() const {
    std::cout << "[PAQUETE] ICMP [" << getTimestampStr() << "]" << std::endl;
}

TCPEvento::TCPEvento(const u_char* packet, int len) : PaqueteEvento("tcp", packet, len) {
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    int ip_header_len = ip_header->ip_hl * 4;
    struct tcphdr* tcp_header = (struct tcphdr*)((u_char*)ip_header + ip_header_len);
    syn_flag = tcp_header->syn;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst, INET_ADDRSTRLEN);
    src_ip = src;
    dst_ip = dst;
}

nlohmann::json TCPEvento::toJSON() const {
    return {{"event", "tcp_packet"}, {"src_ip", src_ip}, {"dst_ip", dst_ip}, {"flags", syn_flag ? "SYN" : "OTHER"}, {"header_bytes", bytesToHex()}, {"timestamp", getTimestampStr()}};
}

void TCPEvento::imprimirResumen() const {
    std::cout << "[PAQUETE] TCP " << src_ip << " -> " << dst_ip << (syn_flag ? " [SYN]" : "") << " [" << getTimestampStr() << "]" << std::endl;
}

UDPEvento::UDPEvento(const u_char* packet, int len) : PaqueteEvento("udp", packet, len) {
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst, INET_ADDRSTRLEN);
    src_ip = src;
    dst_ip = dst;
}

nlohmann::json UDPEvento::toJSON() const {
    return {{"event", "udp_packet"}, {"src_ip", src_ip}, {"dst_ip", dst_ip}, {"header_bytes", bytesToHex()}, {"timestamp", getTimestampStr()}};
}

void UDPEvento::imprimirResumen() const {
    std::cout << "[PAQUETE] UDP " << src_ip << " -> " << dst_ip << " [" << getTimestampStr() << "]" << std::endl;
}
