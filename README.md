# Vista de Red (Network Monitor Tool)

Esta es una herramienta de **monitoreo y gestión de red local** de código abierto, diseñada con una interfaz minimalista y desarrollada en Python. Permite escanear dispositivos conectados, analizar tráfico en tiempo real y gestionar el acceso a internet de dispositivos específicos.

## 🚀 Tecnologías Utilizadas

El proyecto utiliza las siguientes librerías de Python para su funcionamiento:

*   **[Streamlit](https://streamlit.io/)**: Para la creación de la interfaz gráfica web (Dashboard).
*   **[Scapy](https://scapy.net/)**: El núcleo de la herramienta. Se utiliza para la manipulación y envío de paquetes de red (ARP, Sniffing, Spoofing).
*   **[Python-Nmap](https://pypi.org/project/python-nmap/)**: Para realizar escaneos profundos y detección de sistemas operativos.
*   **[Pandas](https://pandas.pydata.org/)**: Para estructurar y mostrar los datos de los dispositivos y el tráfico en tablas.
*   **[Netifaces](https://pypi.org/project/netifaces/)**: Para la detección automática de interfaces de red y gateways.

## 🛠️ Instalación

1.  **Clonar el repositorio**:
    ```bash
    git clone https://github.com/tu-usuario/vista-de-red.git
    cd vista-de-red
    ```

2.  **Instalar dependencias**:
    Se recomienda usar un entorno virtual.
    ```bash
    pip install -r network_tool/requirements.txt
    ```
    *Nota: Necesitarás tener instalado `nmap` en tu sistema (ej: `brew install nmap` en macOS o `apt install nmap` en Linux).*

3.  **Ejecutar la aplicación**:
    Debido a que Scapy manipula paquetes de red a bajo nivel, es necesario ejecutar la herramienta con permisos de administrador (`sudo`).
    ```bash
    sudo streamlit run network_tool/app.py
    ```

## 📂 Estructura del Código (Paso a Paso)

El proyecto está modularizado para facilitar su comprensión y mantenimiento:

### 1. `app.py` (La Interfaz)
Es el punto de entrada. Utiliza **Streamlit** para renderizar tres pestañas principales:
*   **Scanner**: Botones para iniciar escaneo ARP (rápido) o Nmap (profundo). Muestra una tabla con IP, MAC y Fabricante.
*   **Traffic Monitor**: Muestra una gráfica en tiempo real de los protocolos detectados y un "feed" de paquetes capturados.
*   **Access Management**: Permite bloquear el acceso a internet de un dispositivo específico mediante ARP Spoofing.
*   *Función clave*: Gestiona el `st.session_state` para mantener los datos entre recargas de la interfaz.

### 2. `scanner.py` (Escaneo)
*   **`scan_network()`**: Envía peticiones ARP a toda la subred (`ff:ff:ff:ff:ff:ff`). Los dispositivos activos responden con su dirección MAC.
*   **`scan_network_details()`**: Toma los dispositivos encontrados y usa `nmap` para intentar adivinar el Sistema Operativo (OS Fingerprinting) basándose en los puertos abiertos y respuestas TCP/IP.

### 3. `monitor.py` (Sniffer)
*   **`PacketSniffer`**: Clase que ejecuta un hilo en segundo plano (`threading`).
*   Usa `scapy.sniff` para capturar paquetes en la interfaz seleccionada.
*   Analiza capas HTTP, DNS, TCP y UDP para extraer información resumen y mostrarla en el dashboard.

### 4. `manager.py` (Bloqueo/Gestión)
*   Implementa un ataque **Man-in-the-Middle (MitM)** mediante ARP Spoofing para fines de gestión.
*   **`start_blocking()`**: Envía paquetes ARP falsos al objetivo diciéndole que "Yo soy el Router", y al Router diciéndole que "Yo soy el objetivo".
*   Al no reenviar los paquetes (IP Forwarding desactivado o bloqueado), el dispositivo pierde conexión a internet.
*   ** `restore()`**: Restablece las tablas ARP originales cuando se detiene el bloqueo para devolver la conexión.

### 5. `net_utils.py` (Utilidades)
Funciones auxiliares para:
*   Detectar la interfaz de red activa (ej: `en0`, `wlan0`).
*   Obtener la IP local y la Puerta de Enlace (Gateway).
*   Consultar la API de MAC Vendors para identificar el fabricante del dispositivo.

### 6. `assets/custom.css`
Define el diseño **Minimalista Monocromático**. Sobrescribe los estilos por defecto de Streamlit para eliminar colores y forzar una estética de terminal "Hacker" (Negro/Blanco/Gris).

## ⚠️ Aviso Legal

Esta herramienta ha sido creada con fines **educativos y de administración de redes propias**. El uso de técnicas como ARP Spoofing en redes ajenas sin autorización es ilegal. El autor no se hace responsable del mal uso de este software.

---
Hecho con código abierto. Siéntete libre de contribuir.
