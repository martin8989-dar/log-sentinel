import argparse
import os
import time
from parser import LogParser
from detector import ThreatDetector
from notifier import enviar_alerta_discord
from geoip import obtener_ubicacion
from reporter import ReporteSesion


def mostrar_alerta_en_consola(alerta: dict):
    ubicacion = alerta["ubicacion"]
    print("\n------------------------------------------------------------")
    print(f"[ALERTA] {alerta['regla']}")
    print(f" IP Atacante : {alerta['ip']}")
    print(f" Ubicacion   : {ubicacion['pais']}, {ubicacion['ciudad']}")
    print(f" ISP         : {ubicacion['isp']}")
    print(f" Fecha/Hora  : {alerta['timestamp']}")
    print(f" Detalles    : {alerta['detalle']}")
    print("------------------------------------------------------------")


def procesar_linea(linea: str, parser: LogParser, detector: ThreatDetector, reporte: ReporteSesion) -> int:
    reporte.lineas_analizadas += 1
    datos = parser.parse_line(linea)
    if not datos:
        return 0

    alertas = detector.analizar_log(datos)
    for alerta in alertas:
        alerta["ubicacion"] = obtener_ubicacion(alerta["ip"])
        reporte.agregar_alerta(alerta)
        mostrar_alerta_en_consola(alerta)
        enviar_alerta_discord(alerta)

    return len(alertas)


def analizar_archivo_completo(ruta_archivo: str, parser: LogParser, detector: ThreatDetector):
    print(f"[*] Analizando archivo '{ruta_archivo}'...")
    reporte = ReporteSesion(ruta_archivo)

    with open(ruta_archivo, "r", encoding="utf-8", errors="replace") as archivo:
        for linea in archivo:
            procesar_linea(linea, parser, detector, reporte)

    print(f"\n[*] Analisis finalizado. Lineas leidas: {reporte.lineas_analizadas} | Alertas: {reporte.total_alertas}")
    reporte.finalizar()


def abrir_log(ruta_archivo: str):
    archivo = open(ruta_archivo, "r", encoding="utf-8", errors="replace")
    inodo = os.fstat(archivo.fileno()).st_ino
    return archivo, inodo


def log_fue_rotado(ruta_archivo: str, inodo_actual: int, posicion_actual: int) -> bool:
    try:
        estado = os.stat(ruta_archivo)
    except FileNotFoundError:
        return False

    if estado.st_ino != inodo_actual:
        return True
    if estado.st_size < posicion_actual:
        return True
    return False


def monitorear_en_vivo(ruta_archivo: str, parser: LogParser, detector: ThreatDetector):
    reporte = ReporteSesion(ruta_archivo)
    archivo, inodo = abrir_log(ruta_archivo)
    archivo.seek(0, 2)
    print(f"[*] Monitoreando '{ruta_archivo}' en vivo (Ctrl+C para salir)...")

    linea_pendiente = ""

    try:
        while True:
            fragmento = archivo.readline()

            if fragmento:
                linea_pendiente += fragmento
                if linea_pendiente.endswith("\n"):
                    procesar_linea(linea_pendiente, parser, detector, reporte)
                    linea_pendiente = ""
                continue

            if log_fue_rotado(ruta_archivo, inodo, archivo.tell()):
                print("[*] Rotacion de log detectada, abriendo el archivo nuevo...")
                archivo.close()
                archivo, inodo = abrir_log(ruta_archivo)
                linea_pendiente = ""
                continue

            time.sleep(0.5)
    finally:
        archivo.close()
        reporte.finalizar()


def main():
    cli = argparse.ArgumentParser(description="Log Sentinel - Detector de ataques en logs web")
    cli.add_argument("--file", required=True, help="Ruta del archivo de logs a revisar (ej. sample.log)")
    cli.add_argument("--live", action="store_true", help="Monitorear nuevas lineas en tiempo real")
    argumentos = cli.parse_args()

    parser = LogParser()
    detector = ThreatDetector()

    try:
        if argumentos.live:
            monitorear_en_vivo(argumentos.file, parser, detector)
        else:
            analizar_archivo_completo(argumentos.file, parser, detector)
    except FileNotFoundError:
        print(f"[error] No se encontro el archivo '{argumentos.file}'. Puedes crear uno de prueba con: python3 mock_logs.py")
    except PermissionError:
        print(f"[error] Sin permisos para leer '{argumentos.file}'. Ejecuta con sudo o agrega tu usuario al grupo 'adm'.")
    except KeyboardInterrupt:
        print("\n[*] Monitoreo detenido.")


if __name__ == "__main__":
    main()
