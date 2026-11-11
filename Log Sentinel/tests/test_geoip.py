# ==============================================================================
# Pruebas Unitarias - GeoIP
# Autor: Martín Celedón (GitHub: https://github.com/martin8989-dar)
# ==============================================================================

import pytest
import geoip


@pytest.fixture(autouse=True)
def limpiar_estado():
    # Cada test parte con la cache vacia y sin pausa por rate limit
    geoip.cache_ubicaciones.clear()
    geoip.pausa_hasta = 0.0
    yield
    geoip.cache_ubicaciones.clear()
    geoip.pausa_hasta = 0.0


class RespuestaFalsa:
    def __init__(self, status_code=200, datos=None, headers=None):
        self.status_code = status_code
        self._datos = datos or {}
        self.headers = headers or {}

    def json(self):
        return self._datos

    def raise_for_status(self):
        pass


@pytest.mark.parametrize("ip", ["127.0.0.1", "192.168.1.1", "10.0.0.50", "172.16.0.1"])
def test_ips_privadas(ip):
    assert geoip.es_ip_privada(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "45.33.32.156", "185.220.101.9"])
def test_ips_publicas(ip):
    assert geoip.es_ip_privada(ip) is False


def test_ip_invalida_se_trata_como_privada():
    assert geoip.es_ip_privada("no-es-una-ip") is True


def test_ip_privada_no_consulta_la_api(monkeypatch):
    def no_deberia_llamarse(*args, **kwargs):
        raise AssertionError("No se debe consultar la API para IPs privadas")

    monkeypatch.setattr(geoip.requests, "get", no_deberia_llamarse)
    resultado = geoip.obtener_ubicacion("192.168.1.100")
    assert resultado["pais"] == "Red local"


def test_ip_publica_y_cache(monkeypatch):
    llamadas = []

    def get_falso(*args, **kwargs):
        llamadas.append(args)
        return RespuestaFalsa(datos={
            "status": "success",
            "country": "United States",
            "city": "Fremont",
            "isp": "Akamai Technologies, Inc.",
        }, headers={"X-Rl": "44", "X-Ttl": "60"})

    monkeypatch.setattr(geoip.requests, "get", get_falso)

    primera = geoip.obtener_ubicacion("45.33.32.156")
    segunda = geoip.obtener_ubicacion("45.33.32.156")

    assert primera["pais"] == "United States"
    assert primera["isp"] == "Akamai Technologies, Inc."
    assert segunda == primera
    # La segunda consulta sale de la cache
    assert len(llamadas) == 1


def test_rate_limit_429_pausa_las_consultas(monkeypatch):
    monkeypatch.setattr(
        geoip.requests, "get",
        lambda *a, **k: RespuestaFalsa(status_code=429, headers={"X-Ttl": "30"}),
    )
    resultado = geoip.obtener_ubicacion("8.8.8.8")

    assert resultado == geoip.UBICACION_DESCONOCIDA
    assert geoip.pausa_hasta > 0
    assert "8.8.8.8" not in geoip.cache_ubicaciones
