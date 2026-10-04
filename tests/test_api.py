import sys
from pathlib import Path

import pytest

# Make the project root importable when pytest is executed on Windows.
ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def get_app():
    try:
        from api.main import app
        return app
    except Exception as exc:
        pytest.fail(f"FastAPI application could not be imported: {exc}")


def test_fastapi_application_imports():
    fastapi = pytest.importorskip("fastapi")
    assert fastapi is not None

    app = get_app()

    assert app is not None


def test_health_endpoint_when_available():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    app = get_app()

    client = TestClient(app)

    response = client.get("/api/health")

    assert response.status_code == 200


def test_required_dashboard_routes_are_registered():
    app = get_app()

    paths = {
        route.path
        for route in app.routes
    }

    expected = {
        "/api/health",
        "/api/dashboard/summary",
        "/api/dashboard/traffic",
        "/api/alerts",
        "/api/incidents",
        "/api/risk/distribution",
        "/api/network/top-sources",
    }

    missing = expected - paths

    assert not missing, (
        "Missing expected API routes: "
        f"{sorted(missing)}"
    )