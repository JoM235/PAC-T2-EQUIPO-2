// Integrante 1: Jose Miguel Castellanos Martinez
#ifndef EVENTO_H
#define EVENTO_H

#include <string>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>

class Evento {
protected:
    std::string tipo;
    std::chrono::system_clock::time_point timestamp;
public:
    virtual ~Evento() = default;
    virtual nlohmann::json toJSON() const = 0;
    virtual void imprimirResumen() const = 0;
    
    std::string getTipo() const { return tipo; }
    std::chrono::system_clock::time_point getTimestamp() const { return timestamp; }
    
    std::string getTimestampStr() const {
        auto tiempo = std::chrono::system_clock::to_time_t(timestamp);
        std::tm tm = *std::localtime(&tiempo);
        char buffer[32];
        strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
        return std::string(buffer);
    }
};
#endif
