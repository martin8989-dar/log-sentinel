from urllib.parse import unquote
from config import (
    CODIGOS_FALLO,
    MAX_INTENTOS_FALLIDOS,
    PATRONES_ATAQUE,
    RUTAS_CRITICAS,
    TIEMPO_ENTRE_ALERTAS,
    VENTANA_TIEMPO_SEGUNDOS,
)


class ThreatDetector:
    # Revisa cada peticion del log para detectar escaneos o fuerza bruta

    def __init__(self):
        # Guardamos las horas en que cada IP tuvo un error 401 o 403
        # Ejemplo: {"192.168.1.50": [hora1, hora2, hora3]}
        self.intentos_por_ip = {}

        # Hora de la ultima alerta enviada por cada combinacion (ip, regla)
        # Ejemplo: {("45.33.32.156", "Ataque de fuerza bruta"): hora}
        self.ultima_alerta = {}

    def puede_alertar(self, ip: str, regla: str, hora_actual) -> bool:
        # Evita repetir la misma alerta de la misma IP durante TIEMPO_ENTRE_ALERTAS segundos
        clave = (ip, regla)
        hora_anterior = self.ultima_alerta.get(clave)

        if hora_anterior and (hora_actual - hora_anterior).total_seconds() < TIEMPO_ENTRE_ALERTAS:
            return False

        self.ultima_alerta[clave] = hora_actual
        return True

    def analizar_log(self, datos_log: dict) -> list:
        alertas = []

        alerta_escaneo = self.detectar_escaneo(datos_log)
        if alerta_escaneo:
            alertas.append(alerta_escaneo)

        alerta_fuerza_bruta = self.detectar_fuerza_bruta(datos_log)
        if alerta_fuerza_bruta:
            alertas.append(alerta_fuerza_bruta)

        return alertas

    def detectar_escaneo(self, datos_log: dict) -> dict:
        # Regla 1: Buscar acceso a archivos sensibles (.env, .git) o inyecciones en la URL
        ruta_limpia = unquote(datos_log["path"]).lower()
        user_agent_limpio = datos_log["user_agent"].lower()
        ip = datos_log["ip"]
        hora = datos_log["timestamp"]
        evidencia = (
            f"{datos_log['method']} {datos_log['path']} (HTTP {datos_log['status']})\n"
            f"User-Agent: {datos_log['user_agent']}"
        )

        for ruta_peligrosa in RUTAS_CRITICAS:
            if ruta_peligrosa in ruta_limpia:
                regla = f"Acceso a ruta sensible ({ruta_peligrosa})"
                if not self.puede_alertar(ip, regla, hora):
                    return None
                return {
                    "regla": regla,
                    "severidad": "ALTA",
                    "ip": ip,
                    "timestamp": hora,
                    "detalle": f"Se detecto un intento de acceso al recurso restringido '{ruta_peligrosa}'.",
                    "evidencia": evidencia,
                }

        texto_completo = f"{ruta_limpia} {user_agent_limpio}"
        for patron in PATRONES_ATAQUE:
            if patron in texto_completo:
                regla = f"Patron de ataque detectado ({patron})"
                if not self.puede_alertar(ip, regla, hora):
                    return None
                return {
                    "regla": regla,
                    "severidad": "CRITICA",
                    "ip": ip,
                    "timestamp": hora,
                    "detalle": f"La peticion contiene una firma asociada a herramientas de escaneo o inyeccion ('{patron}').",
                    "evidencia": evidencia,
                }

        return None

    def detectar_fuerza_bruta(self, datos_log: dict) -> dict:
        # Regla 2: Contar errores 401/403 por IP dentro de una ventana de 60 segundos
        estado = datos_log["status"]
        ip = datos_log["ip"]
        hora_actual = datos_log["timestamp"]

        if estado not in CODIGOS_FALLO:
            return None

        if ip not in self.intentos_por_ip:
            self.intentos_por_ip[ip] = []

        self.intentos_por_ip[ip].append(hora_actual)

        # Filtramos solo los intentos que ocurrieron en los ultimos 60 segundos
        intentos_recientes = []
        for hora_intento in self.intentos_por_ip[ip]:
            diferencia = (hora_actual - hora_intento).total_seconds()
            if diferencia <= VENTANA_TIEMPO_SEGUNDOS:
                intentos_recientes.append(hora_intento)

        self.intentos_por_ip[ip] = intentos_recientes

        regla = "Ataque de fuerza bruta"
        if len(intentos_recientes) >= MAX_INTENTOS_FALLIDOS and self.puede_alertar(ip, regla, hora_actual):
            evidencia = (
                f"{datos_log['method']} {datos_log['path']} (HTTP {datos_log['status']})\n"
                f"User-Agent: {datos_log['user_agent']}"
            )
            return {
                "regla": regla,
                "severidad": "CRITICA",
                "ip": ip,
                "timestamp": hora_actual,
                "detalle": (
                    f"La IP supero el limite permitido con {len(intentos_recientes)} respuestas "
                    f"fallidas (401/403) en menos de {VENTANA_TIEMPO_SEGUNDOS} segundos."
                ),
                "evidencia": evidencia,
            }

        return None
