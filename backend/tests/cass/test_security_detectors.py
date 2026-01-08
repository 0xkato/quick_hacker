"""Tests for security detection tools."""

import pytest
import tempfile
from pathlib import Path
from cass.tools.security_detectors import SecurityDetectors


@pytest.fixture
def vulnerable_project():
    """Create a project with security issues."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "config.py").write_text('''
API_KEY = "sk-1234567890abcdef"
DATABASE_URL = "postgresql://user:password123@localhost/db"
''')

        (Path(tmpdir) / "auth.py").write_text('''
import os
import subprocess

def login(username, password):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)

def run_command(cmd):
    subprocess.call(cmd, shell=True)

def read_file(filename):
    with open(filename, 'r') as f:
        return f.read()
''')

        (Path(tmpdir) / "memory.c").write_text('''
void vulnerable_function(char *input) {
    char buffer[100];
    strcpy(buffer, input);

    int *ptr = malloc(sizeof(int));
    free(ptr);
    *ptr = 10;  // use after free
}
''')
        yield tmpdir


def test_find_secrets(vulnerable_project):
    """Find hardcoded secrets."""
    detectors = SecurityDetectors(vulnerable_project)
    secrets = detectors.find_secrets()
    assert len(secrets) >= 2
    assert any("API_KEY" in s["name"] for s in secrets)


def test_find_sql_sinks(vulnerable_project):
    """Find SQL query sinks."""
    detectors = SecurityDetectors(vulnerable_project)
    sinks = detectors.find_sinks()
    sql_sinks = [s for s in sinks if s["type"] == "sql"]
    assert len(sql_sinks) >= 1


def test_find_command_sinks(vulnerable_project):
    """Find command execution sinks."""
    detectors = SecurityDetectors(vulnerable_project)
    sinks = detectors.find_sinks()
    cmd_sinks = [s for s in sinks if s["type"] == "command"]
    assert len(cmd_sinks) >= 1


def test_find_memory_issues(vulnerable_project):
    """Find memory safety issues."""
    detectors = SecurityDetectors(vulnerable_project)
    issues = detectors.find_memory_issues()
    assert len(issues) >= 1
