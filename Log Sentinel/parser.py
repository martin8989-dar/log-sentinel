# ==============================================================================
# Log Sentinel - Log Parser & Automated Threat/Brute-Force Detector
# Desarrollado por: Martín Celedón (GitHub: https://github.com/martin8989-dar)
# Especialidad: Ciberseguridad Defensiva / Blue Team
# Licencia: MIT
# ==============================================================================

import re
from datetime import datetime
from config import LOG_REGEX


class LogParser:
    # Clase para leer cada linea del log y separar sus campos

    def parse_line(self, linea: str) -> dict:
        linea = linea.strip()
        if not linea:
            return None

        coincidencia = re.match(LOG_REGEX, linea)
        if not coincidencia:
            # Si la linea no coincide con el formato de Apache/Nginx, la ignoramos
            return None

        ip, fecha_texto, metodo, ruta, codigo_http, tamano, user_agent = coincidencia.groups()

        try:
            # Quitamos la zona horaria (+0000) para parsear la fecha mas facil
            fecha_sin_zona = fecha_texto.split(" ")[0]
            fecha = datetime.strptime(fecha_sin_zona, "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return None

        return {
            "ip": ip,
            "timestamp": fecha,
            "method": metodo,
            "path": ruta,
            "status": int(codigo_http),
            "user_agent": user_agent,
        }
