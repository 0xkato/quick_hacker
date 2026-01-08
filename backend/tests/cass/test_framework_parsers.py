"""Tests for framework detection and parsing."""

import pytest
import tempfile
from pathlib import Path
from cass.tools.framework_parsers import FrameworkParsers


@pytest.fixture
def flask_project():
    """Create a Flask-like project."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "requirements.txt").write_text("flask==2.0.0\nsqlalchemy==1.4.0\n")
        (Path(tmpdir) / "app.py").write_text('''
from flask import Flask, request
app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    return "ok"

@app.route('/users/<int:user_id>')
def get_user(user_id):
    return str(user_id)
''')
        yield tmpdir


@pytest.fixture
def fastapi_project():
    """Create a FastAPI-like project."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "requirements.txt").write_text("fastapi==0.100.0\nuvicorn\n")
        (Path(tmpdir) / "main.py").write_text('''
from fastapi import FastAPI, Query
app = FastAPI()

@app.get("/items/{item_id}")
async def read_item(item_id: int, q: str = Query(None)):
    return {"item_id": item_id}

@app.post("/users/")
async def create_user(user: dict):
    return user
''')
        yield tmpdir


def test_detect_flask(flask_project):
    """Detect Flask framework."""
    parsers = FrameworkParsers(flask_project)
    frameworks = parsers.detect_frameworks()
    assert "flask" in frameworks["backend"]


def test_detect_fastapi(fastapi_project):
    """Detect FastAPI framework."""
    parsers = FrameworkParsers(fastapi_project)
    frameworks = parsers.detect_frameworks()
    assert "fastapi" in frameworks["backend"]


def test_parse_flask_routes(flask_project):
    """Parse Flask routes."""
    parsers = FrameworkParsers(flask_project)
    routes = parsers.parse_routes()
    assert len(routes) == 2

    login_route = next(r for r in routes if r["path"] == "/login")
    assert "POST" in login_route["methods"]
    assert login_route["handler"] == "login"


def test_parse_fastapi_routes(fastapi_project):
    """Parse FastAPI routes."""
    parsers = FrameworkParsers(fastapi_project)
    routes = parsers.parse_routes()
    assert len(routes) == 2

    items_route = next(r for r in routes if "items" in r["path"])
    assert items_route["method"] == "GET"
