#Proyecto: Monitor híbrido de identidad digital y tráfico anómalo en C++
----------------------------------------------------------------------------

##Descripción general
Herramienta desarrollada en C++ para entornos Linux diseñada para el monitoreo concurrente de la seguridad en red. El sistema supervisa cambios en los identificadores de hardware y red (IP/MAC), realiza capturas de tráfico en tiempo real mediante el filtrado selectivo de paquetes y emplea un motor de análisis estadístico para clasificar eventos anómalos. Al finalizar la ejecución, se consolida la actividad en un reporte persistente en formato JSON.

##Integrantes del equipo
Jose Miguel Castellanos Martinez — Diseño de la clase base Evento y lógica del Módulo de Identidad.

Jonathan Emir Jacobo Martinez — Implementación del Módulo Sniffer y decodificación de protocolos (ARP, ICMP, TCP, UDP).

Brandon Yahir Flores Garcia — Desarrollo del Módulo de Análisis y definición de umbrales de detección.

Juan Carlos Fernández Flores — Implementación del Módulo JSONGen para la persistencia de datos.

------------------------------------------------------------------------------------------------------------------

##Requisitos
Sistema Operativo: Distribuciones basadas en Debian/Ubuntu.

Compilador: g++ con soporte para el estándar C++17.

Librerías de Desarrollo:

libpcap-dev: Para la captura y filtrado de paquetes a nivel de enlace.

nlohmann-json3-dev: Para la serialización de objetos a JSON.
-----------------------------------------------------------------------------------------------------------------
Compilación
Para compilar el proyecto incluyendo las dependencias de hilos y captura de paquetes, ejecute:

Bash
g++ main.cpp Identidad.cpp Sniffer.cpp Analisis.cpp JSONGen.cpp -o monitor -lpcap -pthread

Ejecución
Debido a que el uso de libpcap requiere acceso directo a la interfaz de red en modo promiscuo, el programa debe ejecutarse con privilegios de superusuario:

Bash

sudo ./monitor
Parámetros de entrada requeridos:

Interfaz: Nombre de la interfaz física o lógica (ej. ens33, eth0).

Intervalo identidad: Frecuencia de muestreo en milisegundos para verificar cambios en la configuración de red.

Archivo JSON: Ruta del archivo de salida para el reporte final.
------------------------------------------------------------------------------------------------------------------------------
Enfoque técnico
Arquitectura Multihilo: El sistema utiliza tres hilos de ejecución independientes coordinados mediante un std::atomic<bool> para el control de terminación y std::mutex para garantizar la integridad de la lista global de eventos.

Monitoreo de Identidad: Emplea getifaddrs para la resolución de direcciones IP y lectura directa de archivos de sistema en /sys/class/net/ para obtener la dirección MAC.

Captura de Tráfico (Sniffing): Utiliza filtros BPF (Berkeley Packet Filter) para optimizar la captura, enfocándose únicamente en tráfico relacionado con la IP del host y protocolos específicos (ARP, ICMP, TCP, UDP).

Detección de Anomalías: El motor de análisis evalúa ventanas temporales de tráfico y activa alertas basadas en los siguientes criterios:

ARP: Más de 10 paquetes detectados en menos de un minuto desde una misma IP.

ICMP: Flujo superior a 5 paquetes en la ventana de análisis.

TCP: Detección de más de 20 paquetes (posible escaneo o SYN flood).

Identidad: Más de 3 cambios de IP/MAC detectados recientemente.

Gestión de Memoria: Implementación de punteros inteligentes (std::shared_ptr) para la gestión segura de eventos polimórficos entre los distintos módulos.

Ejemplo de JSON generado
El reporte final organiza los eventos cronológicamente con metadatos técnicos específicos por tipo de protocolo:


{
        "dst_ip": "192.168.199.2",
        "event": "udp_packet",
        "header_bytes": "00 50 56 f3 ee ac 00 0c 29 f6 ea fa 08 00 45 00 00 38 2f 4f 40 00 40 11",
        "src_ip": "192.168.199.131",
        "timestamp": "2026-03-12T18:41:44Z"
    },
    {
        "dst_ip": "192.168.199.2",
        "event": "udp_packet",
        "header_bytes": "00 50 56 f3 ee ac 00 0c 29 f6 ea fa 08 00 45 00 00 38 2f 50 40 00 40 11",
        "src_ip": "192.168.199.131",
        "timestamp": "2026-03-12T18:41:44Z"
    },
    {
        "dst_ip": "192.168.199.131",
        "event": "udp_packet",
        "header_bytes": "00 0c 29 f6 ea fa 00 50 56 f3 ee ac 08 00 45 00 00 98 98 68 00 00 80 11",
        "src_ip": "192.168.199.2",
        "timestamp": "2026-03-12T18:41:44Z"
    },
    {
