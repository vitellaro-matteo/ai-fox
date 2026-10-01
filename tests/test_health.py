from fastapi.testclient import TestClient

from radar.api.main import app


def test_health_answers_without_database():
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
