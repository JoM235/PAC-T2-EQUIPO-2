// Integrante 3: Brandon Yahir Flores Garcia
#include "Analisis.h"
#include <iostream>
#include <algorithm>

AnalisisMonitor::AnalisisMonitor() {
    std::cout << "[Análisis] Módulo de detección de anomalías iniciado" << std::endl;
}

AnalisisMonitor::~AnalisisMonitor() {}

void AnalisisMonitor::analizarEvento(std::shared_ptr<Evento> evento) {
    eventos_recientes.push_back(evento);
    auto ahora = std::chrono::system_clock::now();
    eventos_recientes.erase(
        std::remove_if(eventos_recientes.begin(), eventos_recientes.end(),
            [ahora](const std::shared_ptr<Evento>& e) {
                return std::chrono::duration_cast<std::chrono::minutes>(ahora - e->getTimestamp()).count() > 5;
            }),
        eventos_recientes.end()
    );

    if (evento->getTipo() == "arp") {
        auto arp_evento = std::dynamic_pointer_cast<ARPEvento>(evento);
        if (arp_evento) {
            std::string ip = arp_evento->getSrcIP();
            contador_arp_por_ip[ip]++;
            ultimo_arp_por_ip[ip] = std::chrono::system_clock::now();
        }
    }
}

std::vector<std::shared_ptr<Evento>> AnalisisMonitor::verificarAnomaliasPeriodicas() {
    std::vector<std::shared_ptr<Evento>> anomalias;
    auto ahora = std::chrono::system_clock::now();

    for (const auto& [ip, count] : contador_arp_por_ip) {
        auto it = ultimo_arp_por_ip.find(ip);
        if (it != ultimo_arp_por_ip.end()) {
            auto minutos = std::chrono::duration_cast<std::chrono::minutes>(ahora - it->second).count();
            if (minutos < 1 && count > UMBRAL_ARP_FRECUENTE) {
                anomalias.push_back(std::make_shared<AnomaliaEvento>(
                    "Tráfico ARP anormalmente alto desde " + ip,
                    "Se detectaron " + std::to_string(count) + " paquetes ARP en menos de 1 min"
                ));
            }
        }
    }

    int icmp_count = 0, cambios_recientes = 0, syn_count = 0;
    for (const auto& e : eventos_recientes) {
        if (e->getTipo() == "icmp") icmp_count++;
        else if (e->getTipo() == "cambio_ip" || e->getTipo() == "cambio_mac") cambios_recientes++;
        else if (e->getTipo() == "tcp") syn_count++;
    }

    if (icmp_count > UMBRAL_ICMP_REPETITIVO) {
        anomalias.push_back(std::make_shared<AnomaliaEvento>("Tráfico ICMP excesivo", "Paquetes: " + std::to_string(icmp_count)));
    }
    if (cambios_recientes > 3) {
        anomalias.push_back(std::make_shared<AnomaliaEvento>("Cambios frecuentes de identidad", "Cambios: " + std::to_string(cambios_recientes)));
    }
    if (syn_count > 20) {
        anomalias.push_back(std::make_shared<AnomaliaEvento>("Posible escaneo de puertos o SYN flood", "TCP detectados: " + std::to_string(syn_count)));
    }
    return anomalias;
}

AnomaliaEvento::AnomaliaEvento(const std::string& desc, const std::string& crit) : descripcion(desc), criterio(crit) {
    tipo = "anomaly";
    timestamp = std::chrono::system_clock::now();
}

nlohmann::json AnomaliaEvento::toJSON() const {
    return {{"event", "anomaly"}, {"description", descripcion}, {"criterio", criterio}, {"timestamp", getTimestampStr()}};
}

void AnomaliaEvento::imprimirResumen() const {
    std::cout << "[ANOMALÍA] " << descripcion << " [" << getTimestampStr() << "]" << std::endl;
}
