# Log Sentinel

Script en Python para analizar logs de servidores web (formato Nginx / Apache Combined) y detectar intentos de escaneo o ataques de fuerza bruta. Cuando detecta actividad sospechosa, la muestra por terminal, guarda un registro local, envia la alerta en tiempo real a un canal de Discord y al finalizar genera un reporte ejecutivo en Excel (`.xlsx`) hacia un segundo canal de reportes.

## Estructura del proyecto

- `config.py`: Variables de configuracion, limites de intentos para fuerza bruta, rutas sensibles y expresion regular.
- `parser.py`: Lee cada linea del archivo de log y extrae IP, fecha, metodo HTTP, ruta, codigo de estado y User-Agent.
- `detector.py`: Evalua cada peticion contra dos reglas principales:
  1. **Deteccion de escaneo / inyeccion**: Revisa si buscan rutas como `/.env`, `/.git`, `/wp-login.php`, `/etc/passwd` o si usan herramientas como `sqlmap`, `nmap` o `gobuster`.
  2. **Deteccion de fuerza bruta**: Cuenta cuantos errores `401` o `403` tiene una misma IP. Si llega a 5 fallos en menos de 60 segundos, dispara una alerta.

  Para evitar spam en el canal, una misma IP no repite la misma alerta durante 5 minutos.
- `geoip.py`: Consulta el pais, ciudad y proveedor (ISP) de la IP atacante usando la API publica de ip-api.com. Mantiene las respuestas en cache y omite las IPs de red local.
- `notifier.py`: Envia cada alerta en tiempo real a Discord diferenciando severidad por color (`ALTA` en naranja y `CRITICA` en rojo con mencion `@here`), incluye el comando de bloqueo listo para `ufw`, enlaces directos a AbuseIPDB, VirusTotal y Shodan, guarda una copia en `alertas_detectadas.txt` y registra las IPs atacantes unicas en `ips_bloqueadas.txt`.
- `reporter.py`: Consolida las metricas de la sesion, genera una tabla lineal en Microsoft Excel (`.xlsx`) con el registro completo de incidentes y la adjunta automaticamente al canal de reportes en Discord.
- `mock_logs.py`: Genera un archivo `sample.log` con 20 accesos normales y 10 ataques para probar el sistema sin necesitar un servidor web activo.
- `main.py`: Punto de entrada por linea de comandos (`--file` y `--live`). En modo `--live` detecta cuando `logrotate` rota el archivo de logs y continua la lectura sin perder eventos.

## Instalacion y uso

1. Clonar el repositorio y crear el entorno virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Configurar los Webhooks de Discord:

```bash
cp .env.example .env
```
Editar el archivo `.env` y colocar las URLs en `DISCORD_WEBHOOK_URL` (canal de alertas en vivo) y `DISCORD_WEBHOOK_REPORTES` (canal para el informe y archivo Excel).

3. Generar logs de prueba y ejecutar:

```bash
# Crear el archivo sample.log
python3 mock_logs.py

# Analizar el archivo completo y enviar el reporte en Excel
python3 main.py --file sample.log

# Modo en vivo (monitoreo continuo)
python3 main.py --file sample.log --live
```

## Salida en consola

```text
[*] Analizando archivo 'sample.log'...

------------------------------------------------------------
[ALERTA] Acceso a ruta sensible (/.env)
 IP Atacante : 45.33.32.156
 Ubicacion   : United States, Fremont
 ISP         : Akamai Technologies, Inc.
 Fecha/Hora  : 2026-11-07 02:49:34
 Detalles    : Se detecto un intento de acceso al recurso restringido '/.env'.
------------------------------------------------------------
   [ok] Alerta enviado a Discord.

------------------------------------------------------------
[ALERTA] Ataque de fuerza bruta
 IP Atacante : 185.220.101.9
 Ubicacion   : Germany, Brandenburg an der Havel
 ISP         : Stiftung Erneuerbare Freiheit
 Fecha/Hora  : 2026-11-07 02:49:55
 Detalles    : La IP supero el limite permitido con 5 respuestas fallidas (401/403) en menos de 60 segundos.
------------------------------------------------------------
   [ok] Alerta enviado a Discord.

[*] Analisis finalizado. Lineas leidas: 30 | Alertas: 5
[*] Reporte en Excel guardado en 'reportes/reporte_2026-11-09_02-08-48.xlsx'
   [ok] Reporte enviado a Discord.
```

## Uso en un servidor real (Linux)

Probado con Nginx en Ubuntu/Debian. Los pasos son los mismos para Apache cambiando la ruta del log (`/var/log/apache2/access.log`).

1. Clonar el proyecto en el servidor e instalar dependencias:

```bash
sudo git clone https://github.com/TU_USUARIO/log-sentinel.git /opt/log-sentinel
cd /opt/log-sentinel
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt
sudo cp .env.example .env
```

2. Dar permiso de lectura sobre los logs. En Ubuntu los logs de Nginx pertenecen al grupo `adm`:

```bash
sudo useradd --system --no-create-home --groups adm logsentinel
sudo chown -R logsentinel /opt/log-sentinel
```

3. Crear el servicio en `/etc/systemd/system/log-sentinel.service`:

```ini
[Unit]
Description=Log Sentinel - Monitor de logs web
After=network-online.target nginx.service

[Service]
User=logsentinel
WorkingDirectory=/opt/log-sentinel
ExecStart=/opt/log-sentinel/.venv/bin/python -u main.py --file /var/log/nginx/access.log --live
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

4. Activarlo y verificar su estado:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now log-sentinel
sudo journalctl -u log-sentinel -f
```

## Mitigacion activa con iptables / ufw (Linux)

Para pasar de deteccion pasiva a bloqueo activo en el firewall del servidor (al estilo Fail2ban), se puede invocar `ufw` o `iptables` con `subprocess`:

Con `ufw`:
```python
import subprocess

def bloquear_ip(ip):
    subprocess.run(["sudo", "ufw", "insert", "1", "deny", "from", ip], check=True)
```

Con `iptables`:
```python
import subprocess

def bloquear_ip(ip):
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
```

Nota: Si se activa el bloqueo automatico conviene mantener una lista blanca de IPs propias para evitar bloqueos accidentales.

---
Autor: Martín Celedón
