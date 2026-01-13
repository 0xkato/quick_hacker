# Quick Hack Architecture Reference

> **Purpose:** Comprehensive architecture reference for existing team members with ASCII diagrams.

---

## Section 1: High-Level System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           QUICK HACK SYSTEM                                 │
│                 AI-Powered Security Vulnerability Research                  │
└─────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────┐
                              │   Frontend  │
                              │  (Next.js)  │
                              └──────┬──────┘
                                     │
                         HTTP/REST   │   WebSocket
                         ───────────►│◄───────────
                                     │
                              ┌──────▼──────┐
                              │   Backend   │
                              │  (FastAPI)  │
                              └──────┬──────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
              ▼                      ▼                      ▼
       ┌─────────────┐        ┌─────────────┐        ┌─────────────┐
       │  Repo Mgmt  │        │   Agents    │        │ LLM Service │
       │  (Clone/    │        │  (ReAct/    │        │ (Anthropic/ │
       │   Browse)   │        │  Ultrathink)│        │  OpenAI/    │
       └─────────────┘        └─────────────┘        │  Ollama)    │
                                     │               └─────────────┘
                                     │
                              ┌──────▼──────┐
                              │  Findings   │
                              │  Database   │
                              └─────────────┘
```

**Core Flow:**
1. User clones a repository via frontend
2. User configures and starts a security agent
3. Agent analyzes code using LLM + tools
4. Findings stream back via WebSocket
5. User reviews findings with code context

---

## Section 2: Backend Services Map

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            BACKEND SERVICES                                 │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   RepoService   │     │  AgentService   │     │   LLMService    │
├─────────────────┤     ├─────────────────┤     ├─────────────────┤
│ clone_repo()    │     │ create_agent()  │     │ chat()          │
│ list_repos()    │     │ start_agent()   │     │ chat_stream()   │
│ get_file_tree() │     │ pause_agent()   │     │ get_provider()  │
│ read_file()     │     │ resume_agent()  │     └────────┬────────┘
│ delete_repo()   │     │ cancel_agent()  │              │
└────────┬────────┘     │ get_status()    │              │
         │              └────────┬────────┘              │
         │                       │                       │
         │              ┌────────▼────────┐              │
         │              │ WebSocketService│◄─────────────┘
         │              ├─────────────────┤
         │              │ broadcast()     │
         │              │ send_progress() │
         │              │ send_finding()  │
         │              │ send_llm_event()│
         │              └────────┬────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  SessionService │     │  FindingService │     │  ReportService  │
├─────────────────┤     ├─────────────────┤     ├─────────────────┤
│ pause_session() │     │ create_finding()│     │ generate_report │
│ resume_session()│     │ list_findings() │     │ export_markdown │
│ save_snapshot() │     │ get_by_agent()  │     │ export_flow_svg │
│ load_snapshot() │     │ get_by_severity │     └─────────────────┘
└─────────────────┘     └─────────────────┘
```

**Service Responsibilities:**

| Service | Purpose |
|---------|---------|
| `RepoService` | Git operations, file system access |
| `AgentService` | Agent lifecycle, orchestration |
| `LLMService` | Provider abstraction (Anthropic/OpenAI/Ollama) |
| `WebSocketService` | Real-time client updates |
| `SessionService` | Hibernate/resume scanning sessions |
| `FindingService` | Vulnerability storage and retrieval |
| `ReportService` | Generate investigation reports |

---

## Section 3: Agent Types & Inheritance

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AGENT CLASS HIERARCHY                               │
└─────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────────┐
                              │    BaseAgent    │
                              ├─────────────────┤
                              │ id, repo_id     │
                              │ status          │
                              │ provider_config │
                              ├─────────────────┤
                              │ start()         │
                              │ pause()         │
                              │ resume()        │
                              │ cancel()        │
                              │ request_pause() │
                              │ is_pausable()   │
                              │ get_pause_state │
                              └────────┬────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                  │                  │
                    ▼                  ▼                  ▼
         ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
         │  QuickAuditAgent │ │ UltrathinkAgent  │ │ (Other BaseAgent │
         ├──────────────────┤ ├──────────────────┤ │   subclasses)    │
         │ Pattern matching │ │ 5-gate cascade   │ └──────────────────┘
         │ Fast scanning    │ │ Extended thinking│
         └──────────────────┘ └──────────────────┘


┌─────────────────────────────────────────────────────────────────────────────┐
│                      STANDALONE AGENTS (No BaseAgent)                       │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────┐              ┌──────────────────────┐
  │ ReActSecurityAgent   │              │   DeepAuditAgent     │
  ├──────────────────────┤              ├──────────────────────┤
  │ ReAct loop pattern   │              │ Comprehensive audit  │
  │ Think→Act→Observe    │              │ with PoC generation  │
  │                      │              │                      │
  │ + request_pause()    │              │ + request_pause()    │
  │ + is_pausable()      │              │ + is_pausable()      │
  │ + get_pause_state()  │              │ + get_pause_state()  │
  └──────────────────────┘              └──────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                       AGENT TYPE → CLASS MAPPING                            │
└─────────────────────────────────────────────────────────────────────────────┘

  AgentType (enum)          →    Class Used
  ─────────────────────────────────────────────
  quick_audit               →    QuickAuditAgent
  deep_scan                 →    ReActSecurityAgent (DEEP_SCAN profile)
  strict_analysis           →    ReActSecurityAgent (STRICT profile)
  ultra_strict              →    ReActSecurityAgent (ULTRA_STRICT profile)
  custom                    →    ReActSecurityAgent (custom prompt)
  deep_audit                →    DeepAuditAgent
  ultrathink                →    UltrathinkAgent
```

---

## Section 4: Ultrathink Cascade (Critical Path)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ULTRATHINK 5-GATE VERIFICATION CASCADE                   │
│                   (Uses Anthropic Extended Thinking API)                    │
└─────────────────────────────────────────────────────────────────────────────┘

  Potential Finding
         │
         ▼
  ┌──────────────────┐
  │   GATE 1:        │    "Is this worth investigating?"
  │   Triage         │
  │                  │    Filters: noise, false positives, non-issues
  │   thinking:5000  │    Output: PASS (continue) / REJECT (stop)
  └────────┬─────────┘
           │ PASS
           ▼
  ┌──────────────────┐
  │   GATE 2:        │    "What exactly is the vulnerability?"
  │   Deep Analysis  │
  │                  │    Analyzes: attack vectors, impact, exploitability
  │   thinking:15000 │    Output: detailed vulnerability assessment
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────┐
  │   GATE 3:        │    "Why might this NOT be a vulnerability?"
  │   Devil's        │
  │   Advocate       │    Challenges: assumptions, mitigations, context
  │   thinking:10000 │    Output: counter-arguments, confidence adjustment
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────┐
  │   GATE 4:        │    "Can we prove this is exploitable?"
  │   Proof          │
  │   Generator      │    Constructs: PoC code, exploit chain, test cases
  │   thinking:20000 │    Output: working proof-of-concept
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────┐
  │   GATE 5:        │    "Final verdict with all evidence"
  │   Final Gate     │
  │                  │    Synthesizes: all gates, severity, remediation
  │   thinking:10000 │    Output: CONFIRMED finding or REJECTED
  └────────┬─────────┘
           │
           ▼
    Verified Finding
    (High Confidence)
```

**Key Properties:**
- Each gate uses Anthropic's extended thinking for deep reasoning
- Token budgets control thinking depth per gate
- Gates can REJECT at any point (early termination)
- All thinking traces captured for observability
- Only high-confidence findings survive all 5 gates

---

## Section 5: Agent Execution Flow (Critical Path)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ReAct AGENT EXECUTION LOOP                          │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────┐
  │  Agent Created  │
  │  status=pending │
  └────────┬────────┘
           │
           ▼ start()
  ┌─────────────────┐
  │  status=running │◄─────────────────────────────────────┐
  └────────┬────────┘                                      │
           │                                               │
           ▼                                               │
  ┌─────────────────┐                                      │
  │     THINK       │  LLM analyzes current context        │
  │                 │  "What should I investigate next?"   │
  └────────┬────────┘                                      │
           │                                               │
           ▼                                               │
  ┌─────────────────┐     ┌──────────────┐                │
  │     DECIDE      │────►│ report_finding│───► Finding   │
  │                 │     └──────────────┘    Saved       │
  │  Tool to call?  │                                      │
  └────────┬────────┘                                      │
           │                                               │
           ▼                                               │
  ┌─────────────────┐                                      │
  │   TOOL CALL     │  read_file, search_code,            │
  │                 │  get_call_graph, etc.               │
  └────────┬────────┘                                      │
           │                                               │
           ▼                                               │
  ┌─────────────────┐                                      │
  │    OBSERVE      │  Process tool result                 │
  │                 │  Update investigation context        │
  └────────┬────────┘                                      │
           │                                               │
           ▼                                               │
  ┌─────────────────┐         ┌─────────────────┐         │
  │  More to do?    │───yes──►│   Loop back     │─────────┘
  └────────┬────────┘         └─────────────────┘
           │ no
           ▼
  ┌─────────────────┐
  │ status=completed│
  └─────────────────┘


  PAUSE FLOW (Session Hibernation):
  ─────────────────────────────────

  Running ──► request_pause() ──► status=paused ──► snapshot saved
                                       │
                                       ▼
                               resume() from snapshot
                                       │
                                       ▼
                               status=running (continue loop)
```

---

## Section 6: Frontend-Backend Communication (Critical Path)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FRONTEND-BACKEND COMMUNICATION                           │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────┐                         ┌──────────────────┐
  │     FRONTEND     │                         │     BACKEND      │
  │     (Next.js)    │                         │    (FastAPI)     │
  └────────┬─────────┘                         └────────┬─────────┘
           │                                            │
           │  ══════════ HTTP/REST (Request/Response) ══════════
           │                                            │
           │  POST /repos/clone {url, branch}           │
           │ ──────────────────────────────────────────►│
           │                                            │ clone repo
           │◄────────────────────────────────────────── │
           │  {id, name, path, languages}               │
           │                                            │
           │  POST /agents {repo_id, agent_type, ...}   │
           │ ──────────────────────────────────────────►│
           │                                            │ create agent
           │◄────────────────────────────────────────── │
           │  {id, status: "pending"}                   │
           │                                            │
           │  ══════════ WebSocket (Real-time Stream) ══════════
           │                                            │
           │  WS /ws/{agent_id}                         │
           │ ◄═══════════════════════════════════════► │
           │         bidirectional connection           │
           │                                            │
           │◄──────────── agent_status ─────────────── │
           │  {status: "running", files_analyzed: 5}    │
           │                                            │
           │◄──────────── progress ────────────────── │
           │  {current: 5, total: 20, file: "auth.py"}  │
           │                                            │
           │◄──────────── llm_request ─────────────── │
           │  {summary: "Analyzing authentication..."}  │
           │                                            │
           │◄──────────── tool_detail ─────────────── │
           │  {tool: "read_file", args: {path: "..."}}  │
           │                                            │
           │◄──────────── finding ───────────────────  │
           │  {severity: "high", title: "SQL Injection"}│
           │                                            │
           │◄──────────── session_paused ────────────  │
           │  {snapshot_id: "...", agent_count: 2}      │
           │                                            │

  WebSocket Message Types:
  ┌──────────────────┬────────────────────────────────────────────────┐
  │ agent_status     │ Agent state changes (running/paused/completed) │
  │ finding          │ New vulnerability discovered                   │
  │ progress         │ File analysis progress update                  │
  │ error            │ Error occurred during analysis                 │
  │ log              │ Debug/info log message                         │
  │ llm_request      │ LLM API call initiated                         │
  │ llm_response     │ LLM API response received                      │
  │ tool_detail      │ Tool execution details                         │
  │ phase_handoff    │ Scanner→Analyzer model handoff                 │
  │ session_pausing  │ Session pause initiated                        │
  │ session_paused   │ Session fully paused, snapshot ready           │
  │ session_resumed  │ Session resumed from snapshot                  │
  │ report_ready     │ Investigation report generated                 │
  └──────────────────┴────────────────────────────────────────────────┘
```

---

## Section 7: Authentication Flow (Critical Path)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         JWT AUTHENTICATION FLOW                             │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌──────────┐                                           ┌──────────┐
  │  Client  │                                           │  Server  │
  └────┬─────┘                                           └────┬─────┘
       │                                                      │
       │  1. POST /auth/login {username, password}            │
       │ ────────────────────────────────────────────────────►│
       │                                                      │
       │                                    validate credentials
       │                                    generate tokens    │
       │                                                      │
       │◄──────────────────────────────────────────────────── │
       │  {access_token, refresh_token, expires_in}           │
       │                                                      │
       │  ════════════════════════════════════════════════════
       │  Store tokens (localStorage/memory)
       │  ════════════════════════════════════════════════════
       │                                                      │
       │  2. GET /agents                                      │
       │     Authorization: Bearer <access_token>             │
       │ ────────────────────────────────────────────────────►│
       │                                                      │
       │                                    verify JWT         │
       │                                    extract user_id    │
       │                                                      │
       │◄──────────────────────────────────────────────────── │
       │  {agents: [...]}                                     │
       │                                                      │
       │  ════════════════════════════════════════════════════
       │  Access token expires (15 min default)
       │  ════════════════════════════════════════════════════
       │                                                      │
       │  3. POST /auth/refresh                               │
       │     {refresh_token}                                  │
       │ ────────────────────────────────────────────────────►│
       │                                                      │
       │                                    validate refresh   │
       │                                    issue new access   │
       │                                                      │
       │◄──────────────────────────────────────────────────── │
       │  {access_token, expires_in}                          │
       │                                                      │

  Token Lifetimes:
  ┌────────────────┬─────────────────┐
  │ Access Token   │ 15 minutes      │
  │ Refresh Token  │ 7 days          │
  └────────────────┴─────────────────┘

  Protected Routes:
  ┌────────────────────────────────────────────────────────────┐
  │ All /repos/* endpoints                                     │
  │ All /agents/* endpoints                                    │
  │ All /findings/* endpoints                                  │
  │ All /session/* endpoints                                   │
  │ WebSocket /ws/* connections                                │
  └────────────────────────────────────────────────────────────┘
```

---

## Section 8: Frontend Components Map

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FRONTEND LAYOUT                                   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         TopBar                                       │   │
│  │  [Logo] [Repo Selector ▼] [Settings ⚙] [Theme 🌙] [User 👤]         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌──────────────┬──────────────────────────────────┬───────────────────┐   │
│  │              │                                  │                   │   │
│  │   Sidebar    │         Main Content             │   Right Panel     │   │
│  │              │                                  │                   │   │
│  │  ┌────────┐  │  ┌────────────────────────────┐  │  ┌─────────────┐  │   │
│  │  │ File   │  │  │                            │  │  │   Agent     │  │   │
│  │  │ Tree   │  │  │      Code Viewer           │  │  │   Details   │  │   │
│  │  │        │  │  │                            │  │  │             │  │   │
│  │  │ 📁 src │  │  │  with syntax highlighting  │  │  │  Status     │  │   │
│  │  │  📄 a  │  │  │  and finding annotations   │  │  │  Progress   │  │   │
│  │  │  📄 b  │  │  │                            │  │  │  Tokens     │  │   │
│  │  │ 📁 lib │  │  └────────────────────────────┘  │  │  Cost       │  │   │
│  │  │        │  │                                  │  │             │  │   │
│  │  └────────┘  │  ┌────────────────────────────┐  │  └─────────────┘  │   │
│  │              │  │                            │  │                   │   │
│  │  ┌────────┐  │  │    Findings Panel          │  │  ┌─────────────┐  │   │
│  │  │ Agent  │  │  │                            │  │  │   LLM       │  │   │
│  │  │ List   │  │  │  [Critical] SQL Injection  │  │  │   Activity  │  │   │
│  │  │        │  │  │  [High] XSS in template    │  │  │             │  │   │
│  │  │ 🔍 A1  │  │  │  [Medium] Missing auth     │  │  │  Requests   │  │   │
│  │  │ ⏸ A2  │  │  │                            │  │  │  Responses  │  │   │
│  │  │ ✓ A3  │  │  └────────────────────────────┘  │  │  Tool calls │  │   │
│  │  └────────┘  │                                  │  └─────────────┘  │   │
│  │              │                                  │                   │   │
│  └──────────────┴──────────────────────────────────┴───────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      Bottom Panel (collapsible)                      │   │
│  │  [Flow Viz] [Call Graph] [Timeline] [Console]                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Components:**

| Component | Location | Purpose |
|-----------|----------|---------|
| `FileTree` | Left sidebar | Browse repository files |
| `AgentList` | Left sidebar | Manage agents, start/pause/cancel |
| `CodeViewer` | Center | Display code with syntax highlighting |
| `FindingsPanel` | Center bottom | List and filter findings |
| `AgentDetails` | Right panel | Agent status, progress, token usage |
| `LLMActivity` | Right panel | Real-time LLM request/response stream |
| `FlowVisualization` | Bottom panel | Investigation flow graph |
| `CallGraph` | Bottom panel | Code relationship visualization |

---

## Section 9: Database Schema & Data Models

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DATA LAYER ARCHITECTURE                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│     RepoInfo    │       │      Agent      │       │     Finding     │
├─────────────────┤       ├─────────────────┤       ├─────────────────┤
│ id: str (uuid)  │◄──────│ repo_id: str    │◄──────│ agent_id: str   │
│ url: str        │       │ id: str (uuid)  │       │ repo_id: str    │
│ name: str       │       │ name: str       │       │ id: str (uuid)  │
│ branch: str     │       │ agent_type: enum│       │ severity: enum  │
│ path: str       │       │ status: enum    │       │ title: str      │
│ cloned_at: dt   │       │ provider_config │       │ description: str│
│ languages: []   │       │ custom_prompt   │       │ file_path: str  │
│ file_count: int │       │ target_files: []│       │ line_start: int │
└─────────────────┘       │ focus_areas: [] │       │ line_end: int   │
                          │ created_at: dt  │       │ code_snippet    │
                          │ started_at: dt  │       │ vuln_type: str  │
                          │ completed_at: dt│       │ attack_scenario │
                          │ files_analyzed  │       │ recommended_fix │
                          │ findings_count  │       │ confidence: float│
                          │ error_message   │       │ created_at: dt  │
                          └─────────────────┘       │ metadata: {}    │
                                  │                 └─────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AGENT STATUS ENUM                                 │
│  pending → running → completed                                              │
│              ↓          ↑                                                   │
│           paused ───────┘                                                   │
│              ↓                                                              │
│           failed / cancelled                                                │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                         OBSERVABILITY MODELS                                │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│ LLMInteraction  │       │   ToolDetail    │       │AgentStateSnapshot│
├─────────────────┤       ├─────────────────┤       ├─────────────────┤
│ id: str         │       │ id: str         │       │ id: str         │
│ agent_id: str   │       │ agent_id: str   │       │ agent_id: str   │
│ type: req/res   │       │ tool_name: str  │       │ created_at: dt  │
│ timestamp: dt   │       │ tool_call_id    │       │ status: str     │
│ summary: str    │       │ arguments: {}   │       │ files_analyzed  │
│ full_content    │       │ result: any     │       │ total_files     │
│ messages: []    │       │ success: bool   │       │ current_file    │
│ tools_available │       │ error_message   │       │ findings: []    │
│ tool_calls: []  │       │ code_context    │       │ conversation_   │
│ prompt_tokens   │       │ duration_ms     │       │   history: []   │
│ completion_tkns │       │ llm_reasoning   │       │ flow_nodes: []  │
│ duration_ms     │       │ confidence      │       │ flow_edges: []  │
│ model: str      │       └─────────────────┘       │ total_tokens    │
│ provider: str   │                                 │ total_api_calls │
└─────────────────┘                                 └─────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                      SESSION HIBERNATION MODELS                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────┐         ┌─────────────────────────┐
│    SessionSnapshot      │         │   SessionSnapshotAgent  │
├─────────────────────────┤         ├─────────────────────────┤
│ version: int            │         │ id: str                 │
│ timestamp: str          │◄────────│ agent_type: str         │
│ project_id: str         │  1:N    │ status: str             │
│ agents: []              │─────────│ target_files: []        │
│ findings: []            │         │ processed_files: []     │
│ llm_context: []         │         │ pending_files: []       │
│ ui_state: {}            │         │ current_file: str|null  │
└─────────────────────────┘         │ config: {}              │
                                    └─────────────────────────┘
```

**Storage:**
- In-memory dictionaries (repos, agents, findings)
- File-based persistence for snapshots (`~/.quick_hack/snapshots/`)
- No external database required

---

## Section 10: LLM Provider Integration

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        LLM PROVIDER ARCHITECTURE                            │
└─────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────────┐
                              │  ProviderConfig │
                              ├─────────────────┤
                              │ provider: enum  │
                              │ model: str      │
                              │ api_key: str    │
                              │ base_url: str   │
                              │ temperature     │
                              │ max_tokens      │
                              └────────┬────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                  │                  │
                    ▼                  ▼                  ▼
         ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
         │    ANTHROPIC     │ │     OPENAI       │ │     OLLAMA       │
         ├──────────────────┤ ├──────────────────┤ ├──────────────────┤
         │ Claude 3.5/4     │ │ GPT-4/4o         │ │ Local models     │
         │                  │ │                  │ │                  │
         │ ✓ Native thinking│ │ ✗ No thinking    │ │ ✗ No thinking    │
         │   (extended)     │ │   (simulated)    │ │   (structured)   │
         │                  │ │                  │ │                  │
         │ ✓ Tool use       │ │ ✓ Tool use       │ │ ✓ Tool use       │
         │ ✓ Streaming      │ │ ✓ Streaming      │ │ ✓ Streaming      │
         └──────────────────┘ └──────────────────┘ └──────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                    THINKING MODE IMPLEMENTATIONS                            │
└─────────────────────────────────────────────────────────────────────────────┘

ANTHROPIC (Native Extended Thinking):
┌─────────────────────────────────────────────────────────────────────────────┐
│  Request:                                                                   │
│    thinking: { type: "enabled", budget_tokens: 10000 }                      │
│                                                                             │
│  Response includes:                                                         │
│    content: [                                                               │
│      { type: "thinking", thinking: "Let me analyze..." },                   │
│      { type: "text", text: "Based on my analysis..." }                      │
│    ]                                                                        │
└─────────────────────────────────────────────────────────────────────────────┘

OPENAI (Simulated via System Prompt):
┌─────────────────────────────────────────────────────────────────────────────┐
│  System prompt includes:                                                    │
│    "Before responding, think through the problem step by step              │
│     in <thinking></thinking> tags..."                                       │
│                                                                             │
│  Response parsed for:                                                       │
│    <thinking>reasoning here</thinking>                                      │
│    Actual response here                                                     │
└─────────────────────────────────────────────────────────────────────────────┘

OLLAMA (Structured Output):
┌─────────────────────────────────────────────────────────────────────────────┐
│  Uses JSON mode with schema:                                                │
│    { "thinking": "...", "response": "...", "tool_calls": [...] }           │
│                                                                             │
│  Local execution, no API costs                                              │
│  Model quality varies significantly                                         │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                      DUAL-MODEL CONFIGURATION                               │
└─────────────────────────────────────────────────────────────────────────────┘

For Ultrathink agents, two models can be configured:

  ┌─────────────────┐                    ┌─────────────────┐
  │  Scanner Model  │                    │ Analyzer Model  │
  │  (Fast/Cheap)   │ ───handoff────►    │ (Smart/Expensive)│
  ├─────────────────┤                    ├─────────────────┤
  │ claude-3-haiku  │                    │ claude-3-opus   │
  │ gpt-4o-mini     │                    │ gpt-4           │
  │ llama3:8b       │                    │ llama3:70b      │
  └─────────────────┘                    └─────────────────┘
         │                                        │
         ▼                                        ▼
  • Codebase exploration              • Deep vulnerability analysis
  • Entry point discovery             • Exploit chain construction
  • Sink identification               • Proof of concept generation
  • File relevance scoring            • 5-gate verification cascade
```

**Provider Selection Logic:**
```
if provider == "anthropic":
    use native thinking API
    budget_tokens from config or default 10000
elif provider == "openai":
    inject thinking instructions in system prompt
    parse <thinking> tags from response
elif provider == "ollama":
    use structured JSON output
    local model at base_url (default: localhost:11434)
```

---

## Section 11: Tools & ToolExecutor

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TOOL ARCHITECTURE                                   │
└─────────────────────────────────────────────────────────────────────────────┘

                         ┌─────────────────┐
                         │  ToolExecutor   │
                         ├─────────────────┤
                         │ repo_path: str  │
                         │ tools: {}       │
                         │ call_history: []│
                         └────────┬────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    │             │             │
                    ▼             ▼             ▼
            ┌───────────┐ ┌───────────┐ ┌───────────┐
            │   FILE    │ │  SEARCH   │ │  ANALYSIS │
            │   TOOLS   │ │  TOOLS    │ │   TOOLS   │
            └───────────┘ └───────────┘ └───────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                          AVAILABLE TOOLS                                    │
└─────────────────────────────────────────────────────────────────────────────┘

FILE TOOLS:
┌──────────────────┬──────────────────────────────────────────────────────────┐
│ read_file        │ Read file contents with optional line range              │
│                  │ Args: path, start_line?, end_line?                       │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ list_directory   │ List files and subdirectories                            │
│                  │ Args: path, recursive?                                   │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ get_file_info    │ Get file metadata (size, type, lines)                    │
│                  │ Args: path                                               │
└──────────────────┴──────────────────────────────────────────────────────────┘

SEARCH TOOLS:
┌──────────────────┬──────────────────────────────────────────────────────────┐
│ search_code      │ Regex search across codebase                             │
│                  │ Args: pattern, file_pattern?, max_results?               │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ search_symbols   │ Find function/class definitions                          │
│                  │ Args: symbol_name, symbol_type?                          │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ find_references  │ Find all references to a symbol                          │
│                  │ Args: symbol_name, file_path?                            │
└──────────────────┴──────────────────────────────────────────────────────────┘

ANALYSIS TOOLS:
┌──────────────────┬──────────────────────────────────────────────────────────┐
│ get_call_graph   │ Build call graph from entry point                        │
│                  │ Args: function_name, file_path, depth?                   │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ trace_data_flow  │ Track data from source to sink                           │
│                  │ Args: source_var, file_path, line_number                 │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ get_dependencies │ List imports and dependencies                            │
│                  │ Args: file_path                                          │
└──────────────────┴──────────────────────────────────────────────────────────┘

FINDING TOOLS:
┌──────────────────┬──────────────────────────────────────────────────────────┐
│ report_finding   │ Report a security vulnerability                          │
│                  │ Args: severity, title, description, file_path,           │
│                  │       line_start, vulnerability_type, confidence,        │
│                  │       code_snippet?, attack_scenario?, recommended_fix?  │
└──────────────────┴──────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                       TOOL EXECUTION FLOW                                   │
└─────────────────────────────────────────────────────────────────────────────┘

  LLM Response                ToolExecutor              Result
       │                           │                      │
       │  tool_call: {             │                      │
       │    name: "read_file",     │                      │
       │    arguments: {           │                      │
       │      path: "src/auth.py"  │                      │
       │    }                      │                      │
       │  }                        │                      │
       │                           │                      │
       ├──────────────────────────►│                      │
       │                           │  1. Validate args    │
       │                           │  2. Security check   │
       │                           │     (path traversal) │
       │                           │  3. Execute tool     │
       │                           │  4. Format result    │
       │                           │  5. Log to history   │
       │                           │                      │
       │                           ├─────────────────────►│
       │                           │                      │
       │◄──────────────────────────┼──────────────────────┤
       │                           │                      │
       │  tool_result: {           │                      │
       │    content: "...",        │                      │
       │    success: true          │                      │
       │  }                        │                      │

┌─────────────────────────────────────────────────────────────────────────────┐
│                        SECURITY CONSTRAINTS                                 │
└─────────────────────────────────────────────────────────────────────────────┘

  • All paths resolved relative to repo_path
  • Path traversal blocked (no ../ escaping repo)
  • Read-only operations (no file modification)
  • Execution sandboxed to cloned repository
  • Tool calls logged for audit trail
```

---

## Section 12: Configuration & Settings

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      CONFIGURATION HIERARCHY                                │
└─────────────────────────────────────────────────────────────────────────────┘

  Priority (highest to lowest):

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  1. API Request Parameters                                              │
  │     └─► AgentCreateRequest.provider_config                              │
  │         AgentCreateRequest.scanner_config / analyzer_config             │
  ├─────────────────────────────────────────────────────────────────────────┤
  │  2. Frontend Settings (localStorage)                                    │
  │     └─► APISettings saved in browser                                    │
  ├─────────────────────────────────────────────────────────────────────────┤
  │  3. Environment Variables                                               │
  │     └─► OPENAI_API_KEY, ANTHROPIC_API_KEY, OLLAMA_URL                   │
  ├─────────────────────────────────────────────────────────────────────────┤
  │  4. Application Defaults                                                │
  │     └─► Hardcoded in backend/config.py                                  │
  └─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                      ENVIRONMENT VARIABLES                                  │
└─────────────────────────────────────────────────────────────────────────────┘

  Backend (.env):
  ┌──────────────────────┬────────────────────────────────────────────────────┐
  │ Variable             │ Description                                        │
  ├──────────────────────┼────────────────────────────────────────────────────┤
  │ OPENAI_API_KEY       │ OpenAI API key for GPT models                      │
  │ ANTHROPIC_API_KEY    │ Anthropic API key for Claude models                │
  │ OLLAMA_URL           │ Ollama server URL (default: http://localhost:11434)│
  │ JWT_SECRET_KEY       │ Secret for JWT token signing                       │
  │ REPOS_DIR            │ Directory for cloned repos (default: ./repos)      │
  │ SNAPSHOTS_DIR        │ Directory for session snapshots                    │
  │ MAX_CONCURRENT_AGENTS│ Max parallel agents (default: 3)                   │
  │ LOG_LEVEL            │ Logging verbosity (DEBUG/INFO/WARNING/ERROR)       │
  └──────────────────────┴────────────────────────────────────────────────────┘

  Frontend (.env.local):
  ┌──────────────────────┬────────────────────────────────────────────────────┐
  │ NEXT_PUBLIC_API_URL  │ Backend API URL (default: http://localhost:8000)   │
  │ NEXT_PUBLIC_WS_URL   │ WebSocket URL (default: ws://localhost:8000)       │
  └──────────────────────┴────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                       AGENT TYPE PROFILES                                   │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────┬─────────────┬─────────────┬─────────────────────────────┐
  │ Agent Type      │ Temperature │ Max Tokens  │ System Prompt Focus         │
  ├─────────────────┼─────────────┼─────────────┼─────────────────────────────┤
  │ quick_audit     │ 0.3         │ 4096        │ Fast pattern matching       │
  │ deep_scan       │ 0.5         │ 8192        │ Thorough analysis           │
  │ strict_analysis │ 0.2         │ 8192        │ Low false positives         │
  │ ultra_strict    │ 0.1         │ 8192        │ Minimal false positives     │
  │ deep_audit      │ 0.4         │ 16384       │ Comprehensive with PoC      │
  │ custom          │ user-set    │ user-set    │ User-provided prompt        │
  └─────────────────┴─────────────┴─────────────┴─────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                     ULTRATHINK GATE BUDGETS                                 │
└─────────────────────────────────────────────────────────────────────────────┘

  Default thinking token budgets per gate:

  ┌─────────────────────┬───────────────┬─────────────────────────────────────┐
  │ Gate                │ Budget        │ Purpose                             │
  ├─────────────────────┼───────────────┼─────────────────────────────────────┤
  │ Triage              │ 5,000 tokens  │ Quick severity assessment           │
  │ Deep Analysis       │ 15,000 tokens │ Detailed vulnerability analysis     │
  │ Devil's Advocate    │ 10,000 tokens │ Challenge assumptions               │
  │ Proof Generator     │ 20,000 tokens │ Construct exploit PoC               │
  │ Final Gate          │ 10,000 tokens │ Synthesize verdict                  │
  └─────────────────────┴───────────────┴─────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                      FRONTEND SETTINGS UI                                   │
└─────────────────────────────────────────────────────────────────────────────┘

  Settings Panel (⚙):
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  API Keys                                                               │
  │  ├─ OpenAI API Key:      [••••••••••••••••••] [Test]                   │
  │  ├─ Anthropic API Key:   [••••••••••••••••••] [Test]                   │
  │  └─ Ollama URL:          [http://localhost:11434] [Test]               │
  │                                                                         │
  │  Defaults                                                               │
  │  ├─ Default Provider:    [Anthropic ▼]                                 │
  │  └─ Default Model:       [claude-3-5-sonnet-20241022 ▼]                │
  │                                                                         │
  │  Display                                                                │
  │  ├─ Theme:               [Dark ▼]                                      │
  │  └─ Show Token Counts:   [✓]                                           │
  └─────────────────────────────────────────────────────────────────────────┘
```

---

## Section 13: Quick Reference & File Index

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DIRECTORY STRUCTURE                                 │
└─────────────────────────────────────────────────────────────────────────────┘

quick_hack/
├── backend/
│   ├── main.py                 # FastAPI app entry point
│   ├── config.py               # Configuration & defaults
│   ├── agents/
│   │   ├── base_agent.py       # BaseAgent class (pause support)
│   │   ├── quick_audit_agent.py
│   │   ├── react_agent.py      # ReActSecurityAgent (standalone)
│   │   ├── deep_audit_agent.py # DeepAuditAgent (standalone)
│   │   └── ultrathink_agent.py # 5-gate verification cascade
│   ├── routers/
│   │   ├── repos.py            # Repository CRUD endpoints
│   │   ├── agents.py           # Agent management endpoints
│   │   ├── findings.py         # Finding retrieval endpoints
│   │   ├── auth.py             # JWT authentication
│   │   └── session.py          # Session hibernation endpoints
│   ├── services/
│   │   ├── repo_service.py     # Git clone & file operations
│   │   ├── agent_service.py    # Agent lifecycle management
│   │   ├── llm_service.py      # LLM provider abstraction
│   │   ├── websocket_service.py# Real-time updates
│   │   └── session_service.py  # Snapshot save/restore
│   └── models/
│       ├── schemas.py          # Pydantic models
│       └── enums.py            # Status, Severity, etc.
│
├── frontend/
│   ├── app/                    # Next.js App Router pages
│   ├── components/             # React components
│   ├── lib/
│   │   ├── api.ts              # API client functions
│   │   ├── websocket.ts        # WebSocket connection
│   │   └── store.ts            # State management
│   └── types/
│       └── index.ts            # TypeScript interfaces
│
└── docs/
    └── plans/                  # Architecture & implementation plans

┌─────────────────────────────────────────────────────────────────────────────┐
│                          API ENDPOINTS                                      │
└─────────────────────────────────────────────────────────────────────────────┘

Authentication:
  POST /auth/login              # Get access + refresh tokens
  POST /auth/refresh            # Refresh access token
  POST /auth/logout             # Invalidate tokens

Repositories:
  GET  /repos                   # List all repos
  POST /repos/clone             # Clone new repo
  GET  /repos/{id}              # Get repo details
  GET  /repos/{id}/files        # Get file tree
  GET  /repos/{id}/file         # Get file content

Agents:
  GET  /agents                  # List all agents
  POST /agents                  # Create new agent
  GET  /agents/{id}             # Get agent details
  POST /agents/{id}/start       # Start agent
  POST /agents/{id}/pause       # Pause agent
  POST /agents/{id}/resume      # Resume agent
  POST /agents/{id}/cancel      # Cancel agent
  GET  /agents/{id}/report      # Get investigation report

Findings:
  GET  /findings                # List findings (filter by agent/repo)
  GET  /findings/{id}           # Get finding details

Session:
  POST /session/pause           # Pause all & create snapshot
  POST /session/resume          # Resume from snapshot
  GET  /session/snapshot        # Get snapshot info

WebSocket:
  WS   /ws/{agent_id}           # Real-time agent updates

┌─────────────────────────────────────────────────────────────────────────────┐
│                       COMMON COMMANDS                                       │
└─────────────────────────────────────────────────────────────────────────────┘

Development:
  cd backend && uvicorn main:app --reload    # Start backend (port 8000)
  cd frontend && npm run dev                  # Start frontend (port 3000)

Testing:
  cd backend && pytest                        # Run backend tests
  cd frontend && npm test                     # Run frontend tests

Production:
  docker-compose up                           # Start full stack

┌─────────────────────────────────────────────────────────────────────────────┐
│                       KEY FLOWS SUMMARY                                     │
└─────────────────────────────────────────────────────────────────────────────┘

  1. Clone Repo      → POST /repos/clone → repo stored in REPOS_DIR
  2. Create Agent    → POST /agents → agent created with status=pending
  3. Start Agent     → POST /agents/{id}/start → status=running, WS updates
  4. Agent Works     → ReAct loop: Think→Tool→Observe→Report findings
  5. Pause Session   → POST /session/pause → snapshot saved, agents paused
  6. Resume Session  → POST /session/resume → snapshot loaded, agents resume
  7. Get Report      → GET /agents/{id}/report → markdown + flow visualization
```

---

*Generated: 2026-01-09*
