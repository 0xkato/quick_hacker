"""Tests for engine auto-selection in the planner."""

from campaigns.planner import _select_engine


def test_api_route_gets_schemathesis():
    assert _select_engine({"kind": "api_route", "language": "python"}, "quick") == "schemathesis"


def test_python_native_gets_atheris():
    assert _select_engine({"kind": "native_function", "language": "python"}, "quick") == "atheris"


def test_c_native_gets_aflpp():
    assert _select_engine({"kind": "native_function", "language": "c"}, "quick") == "aflpp"


def test_java_native_gets_jazzer():
    assert _select_engine({"kind": "native_function", "language": "java"}, "quick") == "jazzer"


def test_go_native_gets_gofuzz():
    assert _select_engine({"kind": "native_function", "language": "go"}, "quick") == "go_fuzz"


def test_rust_native_gets_cargo():
    assert _select_engine({"kind": "native_function", "language": "rust"}, "quick") == "cargo_fuzz"


def test_solidity_gets_echidna():
    assert _select_engine({"kind": "native_function", "language": "solidity"}, "quick") == "echidna"


def test_parser_gets_grammarinator():
    assert _select_engine({"kind": "parser", "language": "c"}, "quick") == "grammarinator"


def test_workflow_gets_restler():
    assert _select_engine({"kind": "workflow", "language": "python"}, "quick") == "restler"


def test_protocol_gets_boofuzz():
    assert _select_engine({"kind": "message_consumer", "language": ""}, "quick") == "boofuzz"
