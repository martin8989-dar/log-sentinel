# ==============================================================================
# Log Sentinel - Log Parser & Automated Threat/Brute-Force Detector
# Desarrollado por: Martín Celedón (GitHub: https://github.com/martin8989-dar)
# Especialidad: Ciberseguridad Defensiva / Blue Team
# Licencia: MIT
# ==============================================================================

import os
from collections import Counter
from datetime import datetime
import openpyxl
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side

from config import CARPETA_REPORTES, DISCORD_WEBHOOK_REPORTES
from notifier import publicar_en_discord, webhook_configurado

COLOR_REPORTE = 2046560
TAMANO_MAXIMO_ADJUNTO = 8 * 1024 * 1024

# Estilos para la tabla lineal en Excel
FUENTE_CABECERA = Font(name="Calibri", size=10.5, bold=True, color="FFFFFF")
FUENTE_DATOS = Font(name="Calibri", size=10, color="1F2937")
FUENTE_CODIGO = Font(name="Menlo", size=9.5, color="1F2937")
FUENTE_CRITICA = Font(name="Calibri", size=10, bold=True, color="991B1B")
FUENTE_ALTA = Font(name="Calibri", size=10, bold=True, color="92400E")

RELLENO_CABECERA = PatternFill(start_color="1E3A5F", end_color="1E3A5F", fill_type="solid")
RELLENO_PAR = PatternFill(start_color="F8FAFC", end_color="F8FAFC", fill_type="solid")
RELLENO_IMPAR = PatternFill(start_color="FFFFFF", end_color="FFFFFF", fill_type="solid")
RELLENO_CRITICA = PatternFill(start_color="FEE2E2", end_color="FEE2E2", fill_type="solid")
RELLENO_ALTA = PatternFill(start_color="FEF3C7", end_color="FEF3C7", fill_type="solid")

LADO_BORDE = Side(style="thin", color="CBD5E1")
BORDE_CELDA = Border(left=LADO_BORDE, right=LADO_BORDE, top=LADO_BORDE, bottom=LADO_BORDE)


class ReporteSesion:
    # Acumula las alertas de la sesion, genera una tabla lineal en Excel y la envia a Discord

    def __init__(self, archivo_analizado: str, tipo_reporte: str = "Semanal"):
        os.makedirs(CARPETA_REPORTES, exist_ok=True)

        self.archivo_analizado = archivo_analizado
        self.tipo_reporte = tipo_reporte
        self.inicio = datetime.now()
        self.ruta_excel = os.path.join(CARPETA_REPORTES, f"reporte_{self.inicio:%Y-%m-%d_%H-%M-%S}.xlsx")

        self.lineas_analizadas = 0
        self.total_alertas = 0
        self.alertas_por_severidad = Counter()
        self.alertas_por_ip = Counter()
        self.alertas_por_pais = Counter()
        self.filas_incidentes = []
        self.info_ip = {}

    def agregar_alerta(self, alerta: dict):
        ubicacion = alerta.get("ubicacion", {})
        severidad = alerta.get("severidad", "ALTA")
        ip = alerta["ip"]
        pais = ubicacion.get("pais", "Desconocido")

        self.filas_incidentes.append({
            "timestamp": str(alerta["timestamp"]),
            "severidad": severidad,
            "ip": ip,
            "pais": pais,
            "ciudad": ubicacion.get("ciudad", "-"),
            "isp": ubicacion.get("isp", "-"),
            "regla": alerta["regla"],
            "detalle": alerta["detalle"],
            "evidencia": alerta.get("evidencia", "").replace("\n", " | "),
        })

        self.total_alertas += 1
        self.alertas_por_severidad[severidad] += 1
        self.alertas_por_ip[ip] += 1
        self.alertas_por_pais[pais] += 1
        self.info_ip[ip] = {
            "pais": pais,
            "isp": ubicacion.get("isp", "-"),
        }

    def generar_archivo_excel(self):
        # Crea una sola hoja con una tabla lineal continua de principio a fin
        libro = openpyxl.Workbook()
        libro.properties.creator = "Martín Celedón"
        libro.properties.lastModifiedBy = "Martín Celedón"
        libro.properties.title = "Log Sentinel Security Audit Report"
        libro.properties.subject = "Auditoria de Ciberseguridad Defensiva (Blue Team)"
        libro.properties.description = "Generado por Log Sentinel (https://github.com/martin8989-dar/log-sentinel)"
        hoja = libro.active
        hoja.title = "Incidentes"
        hoja.freeze_panes = "A2"

        columnas = [
            "N°",
            "Fecha y Hora",
            "Severidad",
            "IP Atacante",
            "Pais",
            "Ciudad",
            "Proveedor (ISP)",
            "Regla Disparada",
            "Descripcion",
            "Evidencia HTTP",
        ]

        # Fila 1: Cabecera de la tabla
        hoja.row_dimensions[1].height = 26
        for col_idx, titulo in enumerate(columnas, start=1):
            celda = hoja.cell(row=1, column=col_idx, value=titulo)
            celda.font = FUENTE_CABECERA
            celda.fill = RELLENO_CABECERA
            celda.border = BORDE_CELDA
            celda.alignment = Alignment(horizontal="center" if col_idx <= 5 else "left", vertical="center")

        # Filas siguientes: incidentes en orden cronologico
        for num, inc in enumerate(self.filas_incidentes, start=1):
            fila_actual = num + 1
            hoja.row_dimensions[fila_actual].height = 22
            relleno_fila = RELLENO_PAR if num % 2 == 0 else RELLENO_IMPAR

            valores = [
                num,
                inc["timestamp"],
                inc["severidad"],
                inc["ip"],
                inc["pais"],
                inc["ciudad"],
                inc["isp"],
                inc["regla"],
                inc["detalle"],
                inc["evidencia"],
            ]

            for col_idx, valor in enumerate(valores, start=1):
                celda = hoja.cell(row=fila_actual, column=col_idx, value=valor)
                celda.font = FUENTE_DATOS
                celda.fill = relleno_fila
                celda.border = BORDE_CELDA
                celda.alignment = Alignment(vertical="center")

                if col_idx in [1, 2, 5]:
                    celda.alignment = Alignment(horizontal="center", vertical="center")
                elif col_idx == 3:
                    celda.alignment = Alignment(horizontal="center", vertical="center")
                    if valor == "CRITICA":
                        celda.fill = RELLENO_CRITICA
                        celda.font = FUENTE_CRITICA
                    else:
                        celda.fill = RELLENO_ALTA
                        celda.font = FUENTE_ALTA
                elif col_idx == 4:
                    celda.font = FUENTE_CODIGO
                    celda.alignment = Alignment(horizontal="center", vertical="center")
                elif col_idx == 10:
                    celda.font = FUENTE_CODIGO

        ultima_fila = max(len(self.filas_incidentes) + 1, 2)
        hoja.auto_filter.ref = f"A1:J{ultima_fila}"

        anchos = {
            "A": 7,
            "B": 21,
            "C": 14,
            "D": 18,
            "E": 18,
            "F": 20,
            "G": 28,
            "H": 34,
            "I": 50,
            "J": 56,
        }
        for letra, ancho in anchos.items():
            hoja.column_dimensions[letra].width = ancho

        libro.save(self.ruta_excel)

    def tabla_top_ips(self, cantidad: int = 5) -> str:
        if not self.alertas_por_ip:
            return "```\nSin actividad sospechosa registrada\n```"

        lineas = ["IP ORIGEN        EVENTOS  PAIS"]
        lineas.append("-" * 40)
        for ip, conteo in self.alertas_por_ip.most_common(cantidad):
            pais = self.info_ip[ip]["pais"][:15]
            lineas.append(f"{ip:<16} {conteo:>7}  {pais}")
        return "```\n" + "\n".join(lineas) + "\n```"

    def tabla_paises(self, cantidad: int = 4) -> str:
        if not self.alertas_por_pais:
            return "Sin datos"
        lineas = []
        for pais, conteo in self.alertas_por_pais.most_common(cantidad):
            lineas.append(f"- {pais}: {conteo} incidente(s)")
        return "\n".join(lineas)

    def armar_mensaje(self, fin: datetime) -> dict:
        duracion = str(fin - self.inicio).split(".")[0]
        semana_num = self.inicio.isocalendar()[1]
        anio = self.inicio.year

        criticas = self.alertas_por_severidad.get("CRITICA", 0)
        altas = self.alertas_por_severidad.get("ALTA", 0)
        estado_seguridad = "BAJO RIESGO" if criticas == 0 else "ATENCION REQUERIDA"

        return {
            "username": "Log Sentinel Reportes",
            "embeds": [
                {
                    "author": {
                        "name": f"INFORME DE SEGURIDAD {self.tipo_reporte.upper()} | SEMANA {semana_num} ({anio})",
                    },
                    "title": "Consolidado de Actividad Maliciosa e IPs Detectadas",
                    "description": (
                        f"**Origen:** `{self.archivo_analizado}`\n"
                        f"**Diagnostico:** `{estado_seguridad}`\n"
                        "Se adjunta el registro lineal de auditoria en formato Excel (.xlsx)."
                    ),
                    "color": COLOR_REPORTE,
                    "fields": [
                        {"name": "Peticiones Analizadas", "value": f"`{self.lineas_analizadas:,}`", "inline": True},
                        {"name": "Incidentes Totales", "value": f"`{self.total_alertas}`", "inline": True},
                        {"name": "IPs Sospechosas", "value": f"`{len(self.alertas_por_ip)}`", "inline": True},
                        {"name": "Criticas", "value": f"**{criticas}**", "inline": True},
                        {"name": "Altas", "value": f"**{altas}**", "inline": True},
                        {"name": "Duracion", "value": f"`{duracion}`", "inline": True},
                        {"name": "IPs con Mayor Actividad", "value": self.tabla_top_ips(), "inline": False},
                        {"name": "Distribucion por Pais", "value": self.tabla_paises(), "inline": True},
                    ],
                    "footer": {
                        "text": f"Periodo: {self.inicio:%d/%b/%Y %H:%M} - {fin:%d/%b/%Y %H:%M} | Log Sentinel - Martín Celedón",
                    },
                }
            ],
        }

    def finalizar(self):
        if self.lineas_analizadas == 0:
            print("[*] No se procesaron lineas, no se genera reporte.")
            return

        self.generar_archivo_excel()
        print(f"[*] Reporte en Excel guardado en '{self.ruta_excel}'")

        if not webhook_configurado(DISCORD_WEBHOOK_REPORTES):
            print("   [info] Webhook de reportes no configurado en .env, omitiendo envio a Discord")
            return

        mensaje = self.armar_mensaje(datetime.now())

        if os.path.getsize(self.ruta_excel) > TAMANO_MAXIMO_ADJUNTO:
            mensaje["embeds"][0]["description"] += "\n(El archivo Excel supera el limite de Discord y quedo guardado en el servidor)."
            publicar_en_discord(DISCORD_WEBHOOK_REPORTES, mensaje, "Reporte")
        else:
            publicar_en_discord(DISCORD_WEBHOOK_REPORTES, mensaje, "Reporte", ruta_adjunto=self.ruta_excel)
