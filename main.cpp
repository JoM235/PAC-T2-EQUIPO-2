// Integrantes: Jose Miguel Castellanos Martinez y Jonathan Emir Jacobo Martinez
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <string>
#include <vector>
#include <memory>
#include <csignal>
#include <mutex>
#include "Identidad.h"
#include "Sniffer.h"
#include "Analisis.h"
#include "JSONGen.h"

std::atomic<bool> ejecutar(true);
std::vector<std::shared_ptr<Evento>> eventos_globales;
std::mutex eventos_mutex;

void signal_handler(int signal) {
    if (signal == SIGINT) {
        std::cout << "\nDeteniendo programa..." << std::endl;
        ejecutar = false;
    }
}

int main() {
    signal(SIGINT, signal_handler);
    std::string interfaz;
    int intervalo_identidad_ms;
    std::string archivo_salida;

    std::cout << "=== Monitor Híbrido de Identidad Digital y Tráfico Anómalo ===" << std::endl;
    std::cout << "Ingrese la interfaz de red (ej. ens33): ";
    std::cin >> interfaz;
    std::cout << "Ingrese el tiempo de muestreo para identidad digital (ms): ";
    std::cin >> intervalo_identidad_ms;
    std::cout << "Ingrese el archivo de salida JSON: ";
    std::cin >> archivo_salida;

    try {
        IdentidadMonitor identidad(interfaz, intervalo_identidad_ms);
        SnifferMonitor sniffer(interfaz, identidad.getIPActual());
        AnalisisMonitor analisis;

        std::thread hilo_identidad([&]() {
            while (ejecutar) {
                auto evento = identidad.verificarCambios();
                if (evento) {
                    std::lock_guard<std::mutex> lock(eventos_mutex);
                    eventos_globales.push_back(evento);
                    analisis.analizarEvento(evento);
                    evento->imprimirResumen();
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(intervalo_identidad_ms));
            }
        });

        std::thread hilo_sniffer([&]() {
            sniffer.iniciarCaptura([&](std::shared_ptr<Evento> evento) {
                std::lock_guard<std::mutex> lock(eventos_mutex);
                eventos_globales.push_back(evento);
                analisis.analizarEvento(evento);
                evento->imprimirResumen();
            }, ejecutar);
        });

        std::thread hilo_analisis([&]() {
            while (ejecutar) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                auto anomalias = analisis.verificarAnomaliasPeriodicas();
                for (auto& anomalia : anomalias) {
                    std::lock_guard<std::mutex> lock(eventos_mutex);
                    eventos_globales.push_back(anomalia);
                    anomalia->imprimirResumen();
                }
            }
        });

        hilo_identidad.join();
        hilo_sniffer.join();
        hilo_analisis.join();

        JSONGenerator json_gen(archivo_salida);
        json_gen.generarReporte(eventos_globales);

    } catch (const std::exception& e) {
        std::cerr << "Error crítico: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
