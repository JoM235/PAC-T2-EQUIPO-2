// Integrante 4: Juan Carlos Fernandez Flores
#include "JSONGen.h"
#include <iostream>
#include <fstream>
#include <map>
#include <nlohmann/json.hpp>

JSONGenerator::JSONGenerator(const std::string& archivo) : archivo_salida(archivo) {}
JSONGenerator::~JSONGenerator() {}

bool JSONGenerator::generarReporte(const std::vector<std::shared_ptr<Evento>>& eventos) {
    std::ofstream file(archivo_salida);
    if (!file.is_open()) {
        std::cerr << "Error: No se pudo abrir el archivo " << archivo_salida << std::endl;
        return false;
    }

    nlohmann::json json_array = nlohmann::json::array();
    
    std::map<std::string, int> conteo;
    for (const auto& e : eventos) {
        json_array.push_back(e->toJSON());
        conteo[e->getTipo()]++;
    }

    file << json_array.dump(4) << std::endl;
    file.close();

    std::cout << "\n=== Reporte JSON generado ===" << std::endl;
    std::cout << "Total de eventos: " << eventos.size() << std::endl;
    for (const auto& [tipo, count] : conteo) {
        std::cout << " - " << tipo << ": " << count << std::endl;
    }
    return true;
}
