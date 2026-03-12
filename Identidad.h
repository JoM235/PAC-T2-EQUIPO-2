// Integrante 1: Jose Miguel Castellanos Martinez
#ifndef IDENTIDAD_H
#define IDENTIDAD_H

#include <string>
#include <memory>
#include <chrono>
#include "Evento.h"

class IdentidadMonitor {
private:
    std::string interfaz;
    int intervalo_ms;
    std::string ip_actual;
    std::string mac_actual;
    std::chrono::system_clock::time_point ultimo_cambio;
    
    std::string obtenerIP();
    std::string obtenerMAC();
    bool esInterfazValida();
public:
    IdentidadMonitor(const std::string& iface, int intervalo);
    ~IdentidadMonitor();
    std::shared_ptr<Evento> verificarCambios();
    std::string getIPActual() const { return ip_actual; }
};

class CambioIPEvento : public Evento {
private:
    std::string old_ip;
    std::string new_ip;
public:
    CambioIPEvento(const std::string& old_ip, const std::string& new_ip);
    nlohmann::json toJSON() const override;
    void imprimirResumen() const override;
};

class CambioMACEvento : public Evento {
private:
    std::string old_mac;
    std::string new_mac;
public:
    CambioMACEvento(const std::string& old_mac, const std::string& new_mac);
    nlohmann::json toJSON() const override;
    void imprimirResumen() const override;
};
#endif
