# ==============================================================================
# Log Sentinel - Log Parser & Automated Threat/Brute-Force Detector
# Desarrollado por: Martín Celedón (GitHub: https://github.com/martin8989-dar)
# Especialidad: Ciberseguridad Defensiva / Blue Team
# Licencia: MIT
# ==============================================================================

import json
import os
import time
import requests
from config import DISCORD_WEBHOOK_URL, INTERVALO_ENVIO_DISCORD, MAX_REINTENTOS_DISCORD

ultimo_envio = 0.0

# Colores en decimal para las tarjetas de Discord
COLOR_CRITICO = 15158332  # Rojo
COLOR_ALTO = 15105570     # Naranja


def webhook_configurado(url: str) -> bool:
    return bool(url) and "tu_token_aqui" not in url


def guardar_alerta_en_archivo(alerta: dict, archivo_salida: str = "alertas_detectadas.txt"):
    # Guarda copia local de cada alerta en un archivo de texto
    ubicacion = alerta.get("ubicacion", {})
    severidad = alerta.get("severidad", "ALTA")
    linea = (
        f"[{alerta['timestamp']}] [{severidad}] IP: {alerta['ip']} | "
        f"Pais: {ubicacion.get('pais', '-')} | ISP: {ubicacion.get('isp', '-')} | "
        f"Regla: {alerta['regla']} | Detalle: {alerta['detalle']}\n"
    )
    with open(archivo_salida, "a", encoding="utf-8") as archivo:
        archivo.write(linea)


def registrar_ip_bloqueada(ip: str, archivo_bloqueo: str = "ips_bloqueadas.txt"):
    # Guarda las IPs atacantes (una por linea y sin repetir) para cargarlas en el firewall
    ips_existentes = set()
    if os.path.exists(archivo_bloqueo):
        with open(archivo_bloqueo, "r", encoding="utf-8") as archivo:
            ips_existentes = {linea.strip() for linea in archivo if linea.strip()}

    if ip not in ips_existentes:
        with open(archivo_bloqueo, "a", encoding="utf-8") as archivo:
            archivo.write(ip + "\n")
        print(f"   [lista negra] IP {ip} agregada a '{archivo_bloqueo}'")


def esperar_turno_de_envio():
    # Mantiene una pausa minima entre mensajes para que Discord no bloquee el webhook
    global ultimo_envio
    transcurrido = time.time() - ultimo_envio
    if transcurrido < INTERVALO_ENVIO_DISCORD:
        time.sleep(INTERVALO_ENVIO_DISCORD - transcurrido)
    ultimo_envio = time.time()


def segundos_de_espera(respuesta) -> float:
    try:
        return float(respuesta.json().get("retry_after", 2))
    except ValueError:
        return float(respuesta.headers.get("Retry-After", 2))


def publicar_en_discord(url: str, datos_mensaje: dict, descripcion: str, ruta_adjunto: str = None) -> bool:
    # Envia el mensaje al webhook e incluye el archivo adjunto si corresponde
    for intento in range(1, MAX_REINTENTOS_DISCORD + 1):
        esperar_turno_de_envio()

        try:
            if ruta_adjunto:
                mime_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                with open(ruta_adjunto, "rb") as adjunto:
                    respuesta = requests.post(
                        url,
                        data={"payload_json": json.dumps(datos_mensaje)},
                        files={"files[0]": (os.path.basename(ruta_adjunto), adjunto, mime_type)},
                        timeout=20,
                    )
            else:
                respuesta = requests.post(url, json=datos_mensaje, timeout=5)
        except requests.exceptions.RequestException as error:
            print(f"   [error] Fallo de conexion con Discord (intento {intento}/{MAX_REINTENTOS_DISCORD}): {error}")
            time.sleep(2)
            continue

        if respuesta.status_code == 429:
            espera = segundos_de_espera(respuesta)
            print(f"   [aviso] Discord limito los envios, reintentando en {espera:.1f}s")
            time.sleep(espera)
            continue

        if respuesta.ok:
            print(f"   [ok] {descripcion} enviado a Discord.")
            return True

        print(f"   [error] Discord respondio HTTP {respuesta.status_code}. Revisa la URL del webhook.")
        return False

    print(f"   [error] No se pudo enviar a Discord tras {MAX_REINTENTOS_DISCORD} intentos.")
    return False


def armar_mensaje(alerta: dict) -> dict:
    ip = alerta["ip"]
    ubicacion = alerta.get("ubicacion", {})
    severidad = alerta.get("severidad", "ALTA")
    evidencia = alerta.get("evidencia", alerta["detalle"])
    texto_ubicacion = f"{ubicacion.get('pais', '-')}, {ubicacion.get('ciudad', '-')}"

    enlaces_ip = (
        f"[AbuseIPDB](https://www.abuseipdb.com/check/{ip}) | "
        f"[VirusTotal](https://www.virustotal.com/gui/ip-address/{ip}) | "
        f"[Shodan](https://www.shodan.io/host/{ip})"
    )

    comando_bloqueo = f"sudo ufw insert 1 deny from {ip} to any"
    color_embed = COLOR_CRITICO if severidad == "CRITICA" else COLOR_ALTO
    mencion = "@here Incidente critico detectado" if severidad == "CRITICA" else ""

    return {
        "username": "Log Sentinel",
        "content": mencion,
        "embeds": [
            {
                "author": {
                    "name": "LOG SENTINEL | MONITOR DE SEGURIDAD",
                },
                "title": alerta["regla"],
                "description": alerta["detalle"],
                "color": color_embed,
                "fields": [
                    {"name": "IP Atacante", "value": f"`{ip}`", "inline": True},
                    {"name": "Severidad", "value": f"**{severidad}**", "inline": True},
                    {"name": "Fecha y Hora", "value": f"`{alerta['timestamp']}`", "inline": True},
                    {"name": "Ubicacion", "value": texto_ubicacion, "inline": True},
                    {"name": "Proveedor (ISP)", "value": ubicacion.get("isp", "-"), "inline": True},
                    {"name": "Evidencia en el Log", "value": f"```http\n{evidencia}\n```", "inline": False},
                    {"name": "Comando de Bloqueo (Firewall)", "value": f"```bash\n{comando_bloqueo}\n```", "inline": False},
                    {"name": "Verificar IP", "value": enlaces_ip, "inline": False},
                ],
                "footer": {
                    "text": "Log Sentinel | Desarrollado por Martín Celedón (github.com/martin8989-dar)",
                },
            }
        ],
    }


def enviar_alerta_discord(alerta: dict) -> bool:
    guardar_alerta_en_archivo(alerta)
    registrar_ip_bloqueada(alerta["ip"])

    if not webhook_configurado(DISCORD_WEBHOOK_URL):
        print("   [info] Webhook no configurado en .env, omitiendo envio a Discord")
        return False

    return publicar_en_discord(DISCORD_WEBHOOK_URL, armar_mensaje(alerta), "Alerta")
