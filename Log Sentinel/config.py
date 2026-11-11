# ==============================================================================
# Log Sentinel - Log Parser & Automated Threat/Brute-Force Detector
# Desarrollado por: Martín Celedón (GitHub: https://github.com/martin8989-dar)
# Especialidad: Ciberseguridad Defensiva / Blue Team
# Licencia: MIT
# ==============================================================================

import os
from dotenv import load_dotenv

# Cargamos las variables del archivo .env
load_dotenv()

# Canal principal para alertas en tiempo real
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

# Segundo canal para enviar el resumen y el archivo Excel al terminar el analisis
DISCORD_WEBHOOK_REPORTES = os.getenv("DISCORD_WEBHOOK_REPORTES", "")

CARPETA_REPORTES = "reportes"

# API publica de geolocalizacion (ip-api.com)
GEOIP_API_URL = "http://ip-api.com/json/{ip}"
GEOIP_TIMEOUT = 3

# Pausa entre envios para no superar el limite de 30 mensajes por minuto de Discord
INTERVALO_ENVIO_DISCORD = 2
MAX_REINTENTOS_DISCORD = 3

# Segundos de espera antes de repetir la misma alerta para una misma IP
TIEMPO_ENTRE_ALERTAS = 300

# Umbral para fuerza bruta: 5 fallos (401/403) en menos de 60 segundos
MAX_INTENTOS_FALLIDOS = 5
VENTANA_TIEMPO_SEGUNDOS = 60
CODIGOS_FALLO = [401, 403]

# Rutas sensibles que suelen buscar los escaneres automatizados
RUTAS_CRITICAS = [
    "/.env",
    "/.git",
    "/wp-login.php",
    "/wp-admin",
    "/phpmyadmin",
    "/etc/passwd",
    "/admin",
    "/backup.sql",
    "/config.php",
]

# Firmas basicas de inyeccion web y herramientas de escaneo
PATRONES_ATAQUE = [
    "union select",
    "or 1=1",
    "<script>",
    "../",
    "etc/passwd",
    "sqlmap",
    "nikto",
    "nmap",
    "gobuster",
    "dirbuster",
]

# Expresion regular para logs en formato Nginx / Apache Combined
LOG_REGEX = r'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) (\S+) [^"]+" (\d{3}) (\S+) "[^"]*" "([^"]*)"'
