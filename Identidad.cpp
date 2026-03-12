// Integrante 1: Jose Miguel Castellanos Martinez
#include "Identidad.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

IdentidadMonitor::IdentidadMonitor(const std::string& iface, int intervalo)
    : interfaz(iface), intervalo_ms(intervalo) {
    if (!esInterfazValida()) {
        throw std::runtime_error("Interfaz no válida o no existe: " + interfaz);
    }
    ip_actual = obtenerIP();
    mac_actual = obtenerMAC();
    ultimo_cambio = std::chrono::system_clock::now();
    std::cout << "[Identidad] Monitoreando IP: " << ip_actual << " MAC: " << mac_actual << std::endl;
}

IdentidadMonitor::~IdentidadMonitor() {}

bool IdentidadMonitor::esInterfazValida() {
    std::string path = "/sys/class/net/" + interfaz;
    return access(path.c_str(), F_OK) == 0;
}

std::string IdentidadMonitor::obtenerIP() {
    struct ifaddrs *ifaddr, *ifa;
    char ip[INET_ADDRSTRLEN] = "0.0.0.0";
    if (getifaddrs(&ifaddr) == -1) return "ERROR";
    
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (strcmp(ifa->ifa_name, interfaz.c_str()) == 0 && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
            break;
        }
    }
    freeifaddrs(ifaddr);
    return std::string(ip);
}

std::string IdentidadMonitor::obtenerMAC() {
    std::string path = "/sys/class/net/" + interfaz + "/address";
    std::ifstream file(path);
    if (!file.is_open()) return "00:00:00:00:00:00";
    std::string mac;
    std::getline(file, mac);
    return mac;
}

std::shared_ptr<Evento> IdentidadMonitor::verificarCambios() {
    std::string nueva_ip = obtenerIP();
    std::string nueva_mac = obtenerMAC();

    if (nueva_ip != ip_actual && nueva_ip != "0.0.0.0") {
        auto evento = std::make_shared<CambioIPEvento>(ip_actual, nueva_ip);
        ip_actual = nueva_ip;
        ultimo_cambio = std::chrono::system_clock::now();
        return evento;
    }
    if (nueva_mac != mac_actual && nueva_mac != "00:00:00:00:00:00") {
        auto evento = std::make_shared<CambioMACEvento>(mac_actual, nueva_mac);
        mac_actual = nueva_mac;
        ultimo_cambio = std::chrono::system_clock::now();
        return evento;
    }
    return nullptr;
}

CambioIPEvento::CambioIPEvento(const std::string& old_ip, const std::string& new_ip)
    : old_ip(old_ip), new_ip(new_ip) {
    tipo = "cambio_ip";
    timestamp = std::chrono::system_clock::now();
}

nlohmann::json CambioIPEvento::toJSON() const {
    return {
        {"event", "ip_change"},
        {"old_value", old_ip},
        {"new_value", new_ip},
        {"timestamp", getTimestampStr()}
    };
}

void CambioIPEvento::imprimirResumen() const {
    std::cout << "[EVENTO] Cambio IP: " << old_ip << " -> " << new_ip << " [" << getTimestampStr() << "]" << std::endl;
}

CambioMACEvento::CambioMACEvento(const std::string& old_mac, const std::string& new_mac)
    : old_mac(old_mac), new_mac(new_mac) {
    tipo = "cambio_mac";
    timestamp = std::chrono::system_clock::now();
}

nlohmann::json CambioMACEvento::toJSON() const {
    return {
        {"event", "mac_change"},
        {"old_value", old_mac},
        {"new_value", new_mac},
        {"timestamp", getTimestampStr()}
    };
}

void CambioMACEvento::imprimirResumen() const {
    std::cout << "[EVENTO] Cambio MAC: " << old_mac << " -> " << new_mac << " [" << getTimestampStr() << "]" << std::endl;
}
