# ==============================================================================
# Pruebas Unitarias - ThreatDetector
# Autor: Martín Celedón (GitHub: https://github.com/martin8989-dar)
# ==============================================================================

from datetime import datetime, timedelta
import pytest
from detector import ThreatDetector

HORA_BASE = datetime(2026, 11, 7, 2, 49, 30)


@pytest.fixture
def detector():
    return ThreatDetector()


def peticion(ip="45.33.32.156", metodo="GET", ruta="/", estado=200, agente="Mozilla/5.0", segundos=0):
    return {
        "ip": ip,
        "method": metodo,
        "path": ruta,
        "status": estado,
        "user_agent": agente,
        "timestamp": HORA_BASE + timedelta(seconds=segundos),
    }


# --- Regla 1: rutas sensibles e inyecciones ---

@pytest.mark.parametrize("ruta", ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/"])
def test_rutas_sensibles_generan_alerta_alta(detector, ruta):
    alertas = detector.analizar_log(peticion(ruta=ruta, estado=404, agente="curl/8.0"))

    assert len(alertas) == 1
    assert alertas[0]["severidad"] == "ALTA"
    assert alertas[0]["regla"].startswith("Acceso a ruta sensible")


def test_inyeccion_sql_codificada_en_url(detector):
    # El detector decodifica la URL antes de revisarla (%20 -> espacio)
    ruta = "/usuarios?id=1%20UNION%20SELECT%20null,password%20FROM%20users--"
    alertas = detector.analizar_log(peticion(ruta=ruta, estado=500))

    assert len(alertas) == 1
    assert alertas[0]["severidad"] == "CRITICA"
    assert "union select" in alertas[0]["regla"]


def test_user_agent_de_escaner(detector):
    alertas = detector.analizar_log(peticion(ruta="/productos", agente="sqlmap/1.8#stable"))

    assert len(alertas) == 1
    assert "sqlmap" in alertas[0]["regla"]


def test_evidencia_incluye_metodo_ruta_y_agente(detector):
    alerta = detector.analizar_log(peticion(ruta="/.env", estado=404, agente="curl/8.0"))[0]

    assert "GET /.env (HTTP 404)" in alerta["evidencia"]
    assert "User-Agent: curl/8.0" in alerta["evidencia"]


def test_trafico_normal_no_genera_alertas(detector):
    for i, ruta in enumerate(["/index.html", "/productos", "/contacto", "/css/style.css"]):
        assert detector.analizar_log(peticion(ip="192.168.1.10", ruta=ruta, segundos=i)) == []


# --- Regla 2: fuerza bruta con ventana deslizante ---

def test_fuerza_bruta_alerta_al_quinto_fallo(detector):
    for i in range(4):
        assert detector.analizar_log(peticion(ip="185.220.101.9", metodo="POST", ruta="/login", estado=401, segundos=i * 2)) == []

    alertas = detector.analizar_log(peticion(ip="185.220.101.9", metodo="POST", ruta="/login", estado=401, segundos=10))

    assert len(alertas) == 1
    assert alertas[0]["regla"] == "Ataque de fuerza bruta"
    assert alertas[0]["severidad"] == "CRITICA"


def test_fallos_fuera_de_la_ventana_no_cuentan(detector):
    # 5 fallos separados por 20 segundos: nunca hay 5 dentro de 60s
    for i in range(5):
        alertas = detector.analizar_log(peticion(ip="185.220.101.9", ruta="/login", estado=401, segundos=i * 20))
        assert alertas == []


def test_fallos_de_ips_distintas_no_se_mezclan(detector):
    for i in range(5):
        alertas = detector.analizar_log(peticion(ip=f"203.0.113.{i}", ruta="/login", estado=403, segundos=i))
        assert alertas == []


def test_respuestas_exitosas_no_suman_intentos(detector):
    for i in range(10):
        assert detector.analizar_log(peticion(ruta="/login", estado=200, segundos=i)) == []


# --- Anti-spam ---

def test_anti_spam_silencia_alertas_repetidas(detector):
    assert len(detector.analizar_log(peticion(ruta="/.env", estado=404, segundos=0))) == 1
    assert detector.analizar_log(peticion(ruta="/.env", estado=404, segundos=5)) == []


def test_anti_spam_vuelve_a_alertar_tras_el_periodo_de_gracia(detector):
    assert len(detector.analizar_log(peticion(ruta="/.env", estado=404, segundos=0))) == 1
    assert len(detector.analizar_log(peticion(ruta="/.env", estado=404, segundos=301))) == 1
