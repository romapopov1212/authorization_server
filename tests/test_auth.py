import pytest
from httpx import AsyncClient
from fastapi import FastAPI
from main import app
from tests.conftest import async_client

pytestmark = pytest.mark.asyncio

async def test_sign_up(async_client : AsyncClient):
    response = await async_client.post(
            "/auth/sign-up", json={
            "email": "popovroma054@gmail.com",
            "username" : "rtbf",
            "phone_number" : "89656705235",
            "password": "Ge896189098909&",
        }
    )
    assert response.status_code == 201
