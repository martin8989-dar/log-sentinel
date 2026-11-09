import ipaddress
import time
import requests
from config import GEOIP_API_URL, GEOIP_TIMEOUT

# Cache en memoria para no consultar la misma IP varias veces
cache_ubicaciones = {}

# ip-api permite 45 consultas por minuto en su plan gratuito.
# Si llegamos al limite, dejamos de consultar hasta este momento
pausa_hasta = 0.0

UBICACION_DESCONOCIDA = {"pais": "Desconocido", "ciudad": "Desconocido", "isp": "Desconocido"}


def es_ip_privada(ip: str) -> bool:
    # Las IPs locales (192.168.x.x, 10.x.x.x, 127.0.0.1) no tienen ubicacion publica
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def obtener_ubicacion(ip: str) -> dict:
    global pausa_hasta

    if ip in cache_ubicaciones:
        return cache_ubicaciones[ip]

    if es_ip_privada(ip):
        ubicacion = {"pais": "Red local", "ciudad": "-", "isp": "-"}
        cache_ubicaciones[ip] = ubicacion
        return ubicacion

    # Si estamos pausados por el limite de la API, no consultamos
    if time.time() < pausa_hasta:
        return UBICACION_DESCONOCIDA

    try:
        respuesta = requests.get(
            GEOIP_API_URL.format(ip=ip),
            params={"fields": "status,country,city,isp"},
            timeout=GEOIP_TIMEOUT,
        )

        # ip-api avisa en las cabeceras cuantas consultas quedan (X-Rl)
        # y en cuantos segundos se reinicia el contador (X-Ttl)
        consultas_restantes = respuesta.headers.get("X-Rl")
        segundos_reinicio = int(respuesta.headers.get("X-Ttl", 60))

        if respuesta.status_code == 429:
            pausa_hasta = time.time() + segundos_reinicio
            print(f"   [aviso] Limite de ip-api alcanzado, se pausa la geolocalizacion por {segundos_reinicio}s")
            return UBICACION_DESCONOCIDA

        if consultas_restantes == "0":
            pausa_hasta = time.time() + segundos_reinicio

        respuesta.raise_for_status()
        datos = respuesta.json()

        if datos.get("status") == "success":
            ubicacion = {
                "pais": datos.get("country", "Desconocido"),
                "ciudad": datos.get("city", "Desconocido"),
                "isp": datos.get("isp", "Desconocido"),
            }
            # Solo guardamos en cache las respuestas correctas,
            # asi si la API falla se vuelve a intentar en la proxima alerta
            cache_ubicaciones[ip] = ubicacion
            return ubicacion

    except requests.exceptions.RequestException as error:
        print(f"   [error] No se pudo obtener la ubicacion de {ip}: {error}")
    except ValueError:
        print(f"   [error] Respuesta invalida del servicio de geolocalizacion para {ip}")

    return UBICACION_DESCONOCIDA
