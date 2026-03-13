// Integrante 3: Brandon Yahir Flores Garcia. 
#ifndef ANALISIS_H
#define ANALISIS_H

#include <string>
#include <vector>
#include <memory>
#include <map>
#include <chrono>
#include "Evento.h"
#include "Sniffer.h"

class AnalisisMonitor {
private:
    std::map<std::string, int> contador_arp_por_ip;
    std::map<std::string, std::chrono::system_clock::time_point> ultimo_arp_por_ip;
    std::vector<std::shared_ptr<Evento>> eventos_recientes;
    const int UMBRAL_ARP_FRECUENTE = 10;
    const int UMBRAL_ICMP_REPETITIVO = 5;
public:
    AnalisisMonitor();
    ~AnalisisMonitor();
    void analizarEvento(std::shared_ptr<Evento> evento);
    std::vector<std::shared_ptr<Evento>> verificarAnomaliasPeriodicas();
};

class AnomaliaEvento : public Evento {
private:
    std::string descripcion;
    std::string criterio;
public:
    AnomaliaEvento(const std::string& desc, const std::string& crit);
    nlohmann::json toJSON() const override;
    void imprimirResumen() const override;
};
#endif
