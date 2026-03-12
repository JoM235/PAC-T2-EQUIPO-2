// Integrante 2: Jonathan Emir Jacobo Martinez
#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>
#include <functional>
#include <memory>
#include <atomic>
#include <vector>
#include "Evento.h"
#include <pcap.h>

class SnifferMonitor {
private:
    std::string interfaz;
    std::string ip_local;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
public:
    SnifferMonitor(const std::string& iface, const std::string& ip);
    ~SnifferMonitor();
    void iniciarCaptura(std::function<void(std::shared_ptr<Evento>)> callback, std::atomic<bool>& ejecutar);
};

class PaqueteEvento : public Evento {
protected:
    std::vector<uint8_t> header_bytes;
    std::string src_ip;
    std::string dst_ip;
public:
    PaqueteEvento(const std::string& tipo_paquete, const u_char* packet, int len);
    std::string bytesToHex(int max_bytes = 24) const;
    std::string getSrcIP() const { return src_ip; }
};

class ARPEvento : public PaqueteEvento {
public:
    ARPEvento(const u_char* packet, int len);
    nlohmann::json toJSON() const override;
    void imprimirResumen() const override;
};

class ICMPEvento : public PaqueteEvento {
public:
    ICMPEvento(const u_char* packet, int len);
    nlohmann::json toJSON() const override;
    void imprimirResumen() const override;
};

class TCPEvento : public PaqueteEvento {
private:
    bool syn_flag;
public:
    TCPEvento(const u_char* packet, int len);
    nlohmann::json toJSON() const override;
    void imprimirResumen() const override;
};

class UDPEvento : public PaqueteEvento {
public:
    UDPEvento(const u_char* packet, int len);
    nlohmann::json toJSON() const override;
    void imprimirResumen() const override;
};
#endif
