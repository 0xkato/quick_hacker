from lanes.harness_compiler import compile_harness, _detect_build_system, _safe_name

def test_schemathesis_harness():
    result = compile_harness("schemathesis", {"entrypoint": "GET /api/users", "stateful": False}, "/tmp/repo")
    assert result["language"] == "python"
    assert "schemathesis" in result["code"]
    assert result["deps"] == ["schemathesis", "pytest", "pytest-timeout"]

def test_aflpp_harness():
    result = compile_harness("aflpp", {"entrypoint": "parse_input", "language": "c"}, "/tmp/repo")
    assert result["language"] == "c"
    assert "__AFL_FUZZ" in result["code"]
    assert "afl-clang-fast" in result["build_cmd"]

def test_atheris_harness():
    result = compile_harness("atheris", {"entrypoint": "module:func", "language": "python"}, "/tmp/repo")
    assert result["language"] == "python"
    assert "atheris" in result["code"]

def test_jazzer_harness():
    result = compile_harness("jazzer", {"entrypoint": "com.example:Parser", "language": "java"}, "/tmp/repo")
    assert result["language"] == "java"
    assert "FuzzedDataProvider" in result["code"]

def test_go_fuzz_harness():
    result = compile_harness("go_fuzz", {"entrypoint": "pkg:Parse", "language": "go"}, "/tmp/repo")
    assert result["language"] == "go"
    assert "testing.F" in result["code"]

def test_cargo_fuzz_harness():
    result = compile_harness("cargo_fuzz", {"entrypoint": "lib:parse", "language": "rust"}, "/tmp/repo")
    assert result["language"] == "rust"
    assert "fuzz_target!" in result["code"]

def test_echidna_harness():
    result = compile_harness("echidna", {"entrypoint": "Token.sol:Token", "language": "solidity"}, "/tmp/repo")
    assert result["language"] == "solidity"
    assert "echidna_test" in result["code"]

def test_boofuzz_harness():
    result = compile_harness("boofuzz", {"entrypoint": "server", "language": "python"}, "/tmp/repo", base_url="http://target:9090")
    assert result["language"] == "python"
    assert "boofuzz" in result["code"]

def test_unknown_engine_raises():
    import pytest
    with pytest.raises(ValueError):
        compile_harness("nonexistent", {}, "/tmp")

def test_all_engines_return_required_fields():
    engines = ["schemathesis", "aflpp", "atheris", "hypothesis", "jazzer", "go_fuzz",
               "cargo_fuzz", "echidna", "foundry", "boofuzz", "restler", "grammarinator",
               "sqlsmith", "radamsa"]
    for eng in engines:
        result = compile_harness(eng, {"entrypoint": "test", "language": "python"}, "/tmp/repo")
        assert "code" in result, f"{eng} missing code"
        assert "language" in result, f"{eng} missing language"
        assert "run_cmd" in result, f"{eng} missing run_cmd"
        assert "deps" in result, f"{eng} missing deps"

def test_detect_build_system(tmp_path):
    (tmp_path / "Makefile").touch()
    assert _detect_build_system(str(tmp_path), "c") == "make"

def test_detect_cmake(tmp_path):
    (tmp_path / "CMakeLists.txt").touch()
    assert _detect_build_system(str(tmp_path), "cpp") == "cmake"

def test_safe_name():
    assert _safe_name("GET /api/users/{id}") == "GET__api_users__id"
