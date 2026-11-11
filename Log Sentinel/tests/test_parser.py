# ==============================================================================
# Pruebas Unitarias - LogParser
# Autor: Martín Celedón (GitHub: https://github.com/martin8989-dar)
# ==============================================================================

from datetime import datetime
import pytest
from parser import LogParser


@pytest.fixture
def parser():
    return LogParser()


def test_linea_valida_formato_combined(parser):
    linea = '192.168.1.10 - - [07/Nov/2026:02:45:10 +0000] "GET /index.html HTTP/1.1" 200 4523 "-" "Mozilla/5.0"'
    resultado = parser.parse_line(linea)

    assert resultado == {
        "ip": "192.168.1.10",
        "timestamp": datetime(2026, 11, 7, 2, 45, 10),
        "method": "GET",
        "path": "/index.html",
        "status": 200,
        "user_agent": "Mozilla/5.0",
    }


def test_post_con_query_string(parser):
    linea = '45.33.32.156 - - [07/Nov/2026:02:49:34 +0000] "POST /login?user=admin HTTP/1.1" 401 184 "-" "python-requests/2.31"'
    resultado = parser.parse_line(linea)

    assert resultado["method"] == "POST"
    assert resultado["path"] == "/login?user=admin"
    assert resultado["status"] == 401


def test_tamano_vacio_con_guion(parser):
    # Nginx escribe "-" cuando la respuesta no tiene cuerpo
    linea = '10.0.0.5 - - [07/Nov/2026:02:45:10 +0000] "HEAD / HTTP/1.1" 304 - "-" "curl/8.0"'
    assert parser.parse_line(linea)["status"] == 304


def test_ipv6(parser):
    linea = '2001:db8::1 - - [07/Nov/2026:02:45:10 +0000] "GET / HTTP/1.1" 200 10 "-" "curl/8.0"'
    assert parser.parse_line(linea)["ip"] == "2001:db8::1"


@pytest.mark.parametrize("linea", [
    "",
    "   ",
    "Texto plano sin estructura de log web",
    '1.2.3.4 - - [fecha-rota] "GET / HTTP/1.1" 200 10 "-" "curl"',
    '1.2.3.4 - - [99/Xyz/2026:99:99:99 +0000] "GET / HTTP/1.1" 200 10 "-" "curl"',
])
def test_lineas_invalidas_se_ignoran(parser, linea):
    assert parser.parse_line(linea) is None
