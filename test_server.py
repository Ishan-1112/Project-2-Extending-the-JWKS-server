import json
import pytest
from main import app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_index(client):
    response = client.get('/')
    assert response.status_code == 200
    assert response.data == b"Welcome to the JWKS server!"

def test_jwks(client):
    response = client.get('/jwks')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'keys' in data
    assert len(data['keys']) > 0

def test_auth(client):
    response = client.post('/auth')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'access_token' in data
    assert isinstance(data['access_token'], str)
