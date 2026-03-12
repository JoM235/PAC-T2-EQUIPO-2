// Integrante 4: Juan Carlos Fernandez Flores
#ifndef JSONGEN_H
#define JSONGEN_H

#include <string>
#include <vector>
#include <memory>
#include "Evento.h"

class JSONGenerator {
private:
    std::string archivo_salida;
public:
    JSONGenerator(const std::string& archivo);
    ~JSONGenerator();
    bool generarReporte(const std::vector<std::shared_ptr<Evento>>& eventos);
};
#endif
