from services import agent_orchestrator as ao


def test_codex_done_markers_accept_underscored_tokens() -> None:
    assert ao._codex_text_signals_done("AUDIT_COMPLETE")
    assert ao._codex_text_signals_done("analysis_complete")
    assert ao._codex_text_signals_done("investigation_complete")
    assert ao._codex_text_signals_done("no_more_findings")


def test_codex_done_markers_accept_spaced_phrases() -> None:
    assert ao._codex_text_signals_done("audit complete")
    assert ao._codex_text_signals_done("analysis complete")
    assert ao._codex_text_signals_done("investigation complete")
    assert ao._codex_text_signals_done("No more findings.")


def test_codex_scanner_handoff_markers() -> None:
    assert ao._codex_text_signals_handoff_to_analyzer("SCANNING_COMPLETE")
    assert ao._codex_text_signals_handoff_to_analyzer("scanning complete")
    assert ao._codex_text_signals_handoff_to_analyzer("scan complete")
    assert not ao._codex_text_signals_handoff_to_analyzer("continuing investigation")

