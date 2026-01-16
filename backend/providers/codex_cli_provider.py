from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


DEFAULT_CODEX_GLOBAL_HOME = Path.home() / ".codex"


@dataclass(frozen=True)
class CodexRuntimePaths:
    codex_home: Path
    codex_dir: Path
    config_toml: Path
    auth_json: Path
    limits_json: Path
    cancel_flag: Path


class CodexCLIProvider:
    """
    Codex CLI provider (local `codex` binary, not OpenAI API).

    Runs Codex in JSONL streaming mode and converts Codex events into quick_hack's
    internal event shape used by AgentOrchestrator SDK bridging:
      - agent_text/tool_call/tool_result/turn_complete/error
    """

    provider_type: str = "codex_cli"
    _READ_CHUNK_BYTES: int = 64 * 1024
    _MAX_LINE_BUFFER_BYTES: int = 64 * 1024 * 1024

    def __init__(
        self,
        *,
        repo_path: str,
        project_id: str,
        agent_id: str,
        model: str,
        codex_path: str = "codex",
        mcp_server_name: str = "quickhack",
    ) -> None:
        self.repo_path = str(Path(repo_path))
        self.project_id = project_id
        self.agent_id = agent_id
        self.model = model
        self.codex_path = codex_path
        self.mcp_server_name = mcp_server_name

        self.session_id: str | None = None

        self._runtime = self._compute_runtime_paths()
        self._process: asyncio.subprocess.Process | None = None
        self._process_lock = asyncio.Lock()

    @property
    def codex_home(self) -> str:
        return str(self._runtime.codex_home)

    def _compute_runtime_paths(self) -> CodexRuntimePaths:
        data_dir = Path(os.environ.get("DATA_DIR", "data"))
        codex_home = data_dir / "projects" / self.project_id / ".codex_runtime" / self.agent_id
        codex_dir = codex_home / ".codex"
        return CodexRuntimePaths(
            codex_home=codex_home,
            codex_dir=codex_dir,
            config_toml=codex_dir / "config.toml",
            auth_json=codex_dir / "auth.json",
            limits_json=codex_home / "limits.json",
            cancel_flag=codex_home / "cancel.flag",
        )

    def _ensure_codex_home(self) -> None:
        self._runtime.codex_home.mkdir(parents=True, exist_ok=True)
        self._runtime.codex_dir.mkdir(parents=True, exist_ok=True)
        self._copy_auth_if_present()
        self._write_config_toml()

    def _copy_auth_if_present(self) -> None:
        src_home = Path(os.environ.get("CODEX_GLOBAL_HOME") or DEFAULT_CODEX_GLOBAL_HOME)
        src_auth = src_home / "auth.json"
        if not src_auth.exists():
            return

        # Avoid rewriting if unchanged.
        try:
            if self._runtime.auth_json.exists():
                if src_auth.stat().st_size == self._runtime.auth_json.stat().st_size and int(
                    src_auth.stat().st_mtime
                ) == int(self._runtime.auth_json.stat().st_mtime):
                    return
        except Exception:
            pass

        try:
            shutil.copy2(src_auth, self._runtime.auth_json)
        except Exception:
            # Best-effort: codex will surface auth errors if missing.
            pass

    def _write_config_toml(self) -> None:
        # Resolve path to MCP server entrypoint (added in backend/quickhack_mcp/quickhack_mcp_server.py).
        backend_dir = Path(__file__).resolve().parents[1]
        mcp_server_path = backend_dir / "quickhack_mcp" / "quickhack_mcp_server.py"

        content = "\n".join(
            [
                "[features]",
                "shell_tool=false",
                "web_search_request=false",
                "",
                f"[mcp_servers.{self.mcp_server_name}]",
                f"command = {json.dumps(str(sys.executable))}",
                f"args = [{json.dumps('-u')}, {json.dumps(str(mcp_server_path))}]",
                "",
                f"[mcp_servers.{self.mcp_server_name}.env]",
                f"QUICKHACK_REPO_PATH = {json.dumps(self.repo_path)}",
                f"QUICKHACK_PROJECT_ID = {json.dumps(self.project_id)}",
                f"QUICKHACK_AGENT_ID = {json.dumps(self.agent_id)}",
                f"QUICKHACK_LIMITS_PATH = {json.dumps(str(self._runtime.limits_json))}",
                f"QUICKHACK_CANCEL_PATH = {json.dumps(str(self._runtime.cancel_flag))}",
                "",
            ]
        )
        self._runtime.config_toml.write_text(content, encoding="utf-8")

    def write_turn_limits(self, *, max_runtime_s: float) -> None:
        """
        Write per-turn scan limits for the MCP tool server to consume.

        Stored as wall-clock seconds (not monotonic) so another process can interpret it.
        """
        payload = {"max_runtime_s": float(max(0.0, max_runtime_s))}
        self._runtime.limits_json.write_text(json.dumps(payload), encoding="utf-8")

    def set_cancelled(self, cancelled: bool) -> None:
        if cancelled:
            self._runtime.cancel_flag.write_text("1", encoding="utf-8")
        else:
            try:
                self._runtime.cancel_flag.unlink(missing_ok=True)  # type: ignore[arg-type]
            except Exception:
                pass

    def _build_codex_command(self, *, prompt: str) -> list[str]:
        base: list[str] = [self.codex_path, "exec"]

        # NOTE: `codex exec resume` does not accept --sandbox, so keep flags uniform.
        common: list[str] = [
            "--json",
            "--disable",
            "shell_tool",
            "--disable",
            "web_search_request",
            "--model",
            self.model,
            "--skip-git-repo-check",
        ]

        if self.session_id:
            # Keep the session id as the first positional argument after `resume`
            # for compatibility with `codex exec resume <SESSION_ID> ...`.
            return base + ["resume", self.session_id] + common + [prompt]

        # Initial session: pin working directory via --cd (resume inherits prior cwd).
        return base + common + ["--cd", self.repo_path, prompt]

    def _convert_codex_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Convert a Codex JSON event into quick_hack internal events."""
        etype = (event.get("type") or "").strip()

        if etype == "thread.started":
            thread_id = (event.get("thread_id") or "").strip()
            if thread_id:
                self.session_id = thread_id
                return [{"type": "session_started", "session_id": thread_id}]
            return []

        if etype == "turn.completed":
            return [
                {
                    "type": "turn_complete",
                    "session_id": self.session_id,
                    "usage": event.get("usage"),
                }
            ]

        if etype == "turn.failed":
            err = event.get("error") or {}
            message = err.get("message") if isinstance(err, dict) else str(err)
            return [{"type": "error", "message": str(message)}]

        if etype == "error":
            return [{"type": "error", "message": str(event.get("message") or "")}]

        if etype in ("item.completed", "item.started"):
            item = event.get("item") or {}
            if not isinstance(item, dict):
                return []
            item_type = item.get("type")

            if etype == "item.completed" and item_type == "agent_message":
                text = item.get("text")
                if isinstance(text, str) and text:
                    return [{"type": "agent_text", "text": text}]
                return []

            if item_type == "mcp_tool_call":
                server = str(item.get("server") or "")
                tool = str(item.get("tool") or "")
                item_id = str(item.get("id") or "")
                args = item.get("arguments") if isinstance(item.get("arguments"), dict) else {}
                tool_name = f"mcp__{server}__{tool}" if server and tool else tool

                if etype == "item.started":
                    return [
                        {
                            "type": "tool_call",
                            "id": item_id,
                            "name": tool_name,
                            "args": args,
                        }
                    ]

                # item.completed
                result = item.get("result")
                is_error = bool(item.get("error"))
                return [
                    {
                        "type": "tool_result",
                        "tool_use_id": item_id,
                        "tool_name": tool_name,
                        "result": result,
                        "is_error": is_error,
                        "error": item.get("error"),
                    }
                ]

        return []

    async def start_session(self, *, resume_session_id: str | None = None) -> str:
        self._ensure_codex_home()
        if resume_session_id:
            self.session_id = resume_session_id
        return self.session_id or ""

    async def run_turn(
        self,
        *,
        prompt: str,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> list[dict[str, Any]]:
        self._ensure_codex_home()
        cmd = self._build_codex_command(prompt=prompt)

        env = dict(os.environ)
        # Codex currently loads config and auth from `~/.codex/*`.
        # Make the subprocess HOME point at the per-agent runtime root so
        # `~/.codex/config.toml` resolves to `{codex_home}/.codex/config.toml`.
        env["HOME"] = str(self._runtime.codex_home)
        # Also set CODEX_HOME for forward-compat / explicitness (ignored by some versions).
        env["CODEX_HOME"] = str(self._runtime.codex_dir)

        events: list[dict[str, Any]] = []

        async with self._process_lock:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=self.repo_path,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

        assert self._process.stdout is not None  # for type checker
        try:
            buffer = bytearray()

            def next_delim(buf: bytearray) -> tuple[int, int] | None:
                idx_n = buf.find(b"\n")
                idx_r = buf.find(b"\r")
                if idx_n == -1 and idx_r == -1:
                    return None
                if idx_n == -1:
                    return idx_r, 13
                if idx_r == -1:
                    return idx_n, 10
                if idx_r < idx_n:
                    return idx_r, 13
                return idx_n, 10

            def handle_line(text: str) -> None:
                line = text.strip()
                if not line:
                    return

                parsed: dict[str, Any] | None = None
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        parsed = obj
                except Exception:
                    parsed = {"type": "error", "message": line}

                for ev in self._convert_codex_event(parsed or {}):
                    events.append(ev)
                    if on_event is not None:
                        on_event(ev)

            while True:
                chunk = await self._process.stdout.read(self._READ_CHUNK_BYTES)
                if not chunk:
                    break
                buffer.extend(chunk)

                while True:
                    delim = next_delim(buffer)
                    if delim is None:
                        break
                    idx, delim_byte = delim
                    line_bytes = bytes(buffer[:idx])
                    del buffer[: idx + 1]
                    # Handle CRLF.
                    if delim_byte == 13 and buffer[:1] == b"\n":
                        del buffer[:1]
                    handle_line(line_bytes.decode("utf-8", errors="replace"))

                if len(buffer) > self._MAX_LINE_BUFFER_BYTES:
                    handle_line(
                        json.dumps(
                            {
                                "type": "error",
                                "message": f"Codex output exceeded {self._MAX_LINE_BUFFER_BYTES} bytes without a line break; truncating.",
                            }
                        )
                    )
                    buffer.clear()

            if buffer:
                handle_line(buffer.decode("utf-8", errors="replace"))

            await self._process.wait()
        finally:
            async with self._process_lock:
                self._process = None

        return events

    async def interrupt(self) -> None:
        async with self._process_lock:
            proc = self._process

        if proc is None:
            return

        try:
            proc.send_signal(signal.SIGTERM)
        except ProcessLookupError:
            return
        except Exception:
            try:
                proc.terminate()
            except Exception:
                return

        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
            return
        except asyncio.TimeoutError:
            pass

        try:
            proc.send_signal(signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                return
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except Exception:
            return
