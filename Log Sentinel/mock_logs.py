# ==============================================================================
# Log Sentinel - Log Parser & Automated Threat/Brute-Force Detector
# Desarrollado por: Martín Celedón (GitHub: https://github.com/martin8989-dar)
# Especialidad: Ciberseguridad Defensiva / Blue Team
# Licencia: MIT
# ==============================================================================

from datetime import datetime, timedelta
import random


def crear_logs_prueba(nombre_archivo: str = "sample.log"):
    # Crea un archivo sample.log con 20 visitas normales y 10 ataques para probar el script
    hora_base = datetime.now() - timedelta(minutes=10)
    lineas_log = []

    ips_normales = ["192.168.1.10", "192.168.1.25", "10.0.0.5", "192.168.1.88"]
    rutas_normales = ["/index.html", "/productos", "/contacto", "/login", "/css/style.css", "/img/logo.png"]

    # 20 accesos normales
    for _ in range(20):
        hora_base += timedelta(seconds=random.randint(3, 10))
        ip = random.choice(ips_normales)
        ruta = random.choice(rutas_normales)
        fecha_str = hora_base.strftime("%d/%b/%Y:%H:%M:%S +0000")

        linea = f'{ip} - - [{fecha_str}] "GET {ruta} HTTP/1.1" 200 1520 "-" "Mozilla/5.0 (Windows NT 10.0)"'
        lineas_log.append(linea)

    # 4 intentos de escaneo desde la IP 45.33.32.156
    ip_escaneo = "45.33.32.156"
    ataques_escaneo = [
        ("GET", "/.env", 404, "Mozilla/5.0 (Nmap Scripting Engine)"),
        ("GET", "/.git/config", 403, "gobuster/3.6"),
        ("GET", "/usuarios?id=1%20UNION%20SELECT%20*--", 500, "sqlmap/1.8"),
        ("GET", "/descargar?archivo=../../etc/passwd", 400, "curl/8.0"),
    ]

    for metodo, ruta, codigo, navegador in ataques_escaneo:
        hora_base += timedelta(seconds=2)
        fecha_str = hora_base.strftime("%d/%b/%Y:%H:%M:%S +0000")
        linea = f'{ip_escaneo} - - [{fecha_str}] "{metodo} {ruta} HTTP/1.1" {codigo} 310 "-" "{navegador}"'
        lineas_log.append(linea)

    # 6 intentos fallidos de login seguidos (fuerza bruta) desde la IP 185.220.101.9
    ip_fuerza_bruta = "185.220.101.9"
    for _ in range(6):
        hora_base += timedelta(seconds=3)
        fecha_str = hora_base.strftime("%d/%b/%Y:%H:%M:%S +0000")
        linea = f'{ip_fuerza_bruta} - - [{fecha_str}] "POST /login HTTP/1.1" 401 250 "-" "python-requests/2.31"'
        lineas_log.append(linea)

    with open(nombre_archivo, "w", encoding="utf-8") as archivo:
        for linea in lineas_log:
            archivo.write(linea + "\n")

    print(f"[*] Archivo '{nombre_archivo}' generado (20 accesos normales y 10 de prueba).")


if __name__ == "__main__":
    crear_logs_prueba()
