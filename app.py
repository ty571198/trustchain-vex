import streamlit as st
import networkx as nx
import re
import json
import datetime
from collections import defaultdict
from pyvis.network import Network
import tempfile
import os

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="VulnPath Analyzer",
    page_icon="🔴",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

/* ── Root palette ── */
:root {
  --bg:        #090c10;
  --surface:   #0d1117;
  --panel:     #161b22;
  --border:    #21262d;
  --accent:    #f85149;
  --safe:      #3fb950;
  --warn:      #e3b341;
  --text:      #c9d1d9;
  --muted:     #8b949e;
  --glow-r:    rgba(248,81,73,0.25);
  --glow-g:    rgba(63,185,80,0.25);
}

/* ── Global ── */
html, body, [data-testid="stAppViewContainer"] {
  background-color: var(--bg) !important;
  color: var(--text) !important;
  font-family: 'Rajdhani', sans-serif;
}
[data-testid="stSidebar"] {
  background-color: var(--surface) !important;
  border-right: 1px solid var(--border);
}
code, pre, textarea, .stTextArea textarea {
  font-family: 'Share Tech Mono', monospace !important;
}

/* ── Headers ── */
h1 { font-family: 'Rajdhani', sans-serif; font-weight: 700; letter-spacing: 2px; color: var(--accent) !important; }
h2, h3 { font-family: 'Rajdhani', sans-serif; font-weight: 600; color: var(--text) !important; }

/* ── Inputs ── */
.stTextArea textarea {
  background: var(--panel) !important;
  color: var(--text) !important;
  border: 1px solid var(--border) !important;
  border-radius: 4px !important;
  font-size: 13px !important;
}
.stTextInput input, .stSelectbox select {
  background: var(--panel) !important;
  color: var(--text) !important;
  border: 1px solid var(--border) !important;
}

/* ── Buttons ── */
.stButton > button {
  background: transparent !important;
  border: 1px solid var(--accent) !important;
  color: var(--accent) !important;
  font-family: 'Share Tech Mono', monospace !important;
  letter-spacing: 1px;
  transition: all 0.2s;
}
.stButton > button:hover {
  background: var(--accent) !important;
  color: #fff !important;
  box-shadow: 0 0 14px var(--glow-r);
}

/* ── Cards ── */
.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 20px 24px;
  margin-bottom: 12px;
}
.card-danger {
  border-color: var(--accent);
  box-shadow: 0 0 18px var(--glow-r);
}
.card-safe {
  border-color: var(--safe);
  box-shadow: 0 0 18px var(--glow-g);
}
.badge-danger { color: var(--accent); font-size: 1.1rem; font-weight: 700; }
.badge-safe   { color: var(--safe);   font-size: 1.1rem; font-weight: 700; }
.badge-info   { color: var(--warn);   font-size: 0.95rem; }

/* ── Metric override ── */
[data-testid="metric-container"] {
  background: var(--panel) !important;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 16px;
}

/* ── Divider ── */
hr { border-color: var(--border) !important; }

/* ── Code block ── */
.path-step {
  font-family: 'Share Tech Mono', monospace;
  font-size: 13px;
  color: var(--accent);
}
.path-safe-step { color: var(--safe); }

/* ── Hide streamlit brand ── */
#MainMenu, footer { visibility: hidden; }
[data-testid="stDecoration"] { display:none; }
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  SAMPLE CODE
# ══════════════════════════════════════════════════════════════════════════════
SAMPLE_CODE = r"""#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void log_event(const char *msg) {
    printf("[LOG] %s\n", msg);
}

void process_input(char *data) {
    char buf[64];
    strcpy(buf, data);   // ← buffer overflow (vulnerable)
    log_event(buf);
}

void authenticate(char *user, char *pass) {
    log_event("Authenticating...");
    process_input(pass);
}

void handle_request(char *payload) {
    char *user = strtok(payload, ":");
    char *pass = strtok(NULL, ":");
    authenticate(user, pass);
}

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    handle_request(argv[1]);
    return 0;
}

void unused_func(void) {
    log_event("This is never called");
}
"""

# ══════════════════════════════════════════════════════════════════════════════
#  ANALYSIS ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def extract_call_graph(code: str) -> nx.DiGraph:
    """
    Parse C/C++ source and build a directed call graph.
    Strategy:
      1. Find every function *definition*  (return-type name(...) { )
      2. Inside each function body, find identifiers followed by '(' → calls
    Returns a DiGraph where edge A→B means A calls B.
    """
    G = nx.DiGraph()

    # ── 1. Locate function definitions ────────────────────────────────────────
    # Match: word(s) before the function name, then name, then (params), then {
    func_def_pattern = re.compile(
        r'\b(?:void|int|char|float|double|bool|long|short|unsigned|static\s+\w+|\w+)\s*\*?\s*'
        r'(\w+)\s*\([^)]*\)\s*\{',
        re.MULTILINE,
    )

    # Build list of (name, body_start_pos)
    functions = []
    for m in func_def_pattern.finditer(code):
        fname = m.group(1)
        if fname in ('if', 'while', 'for', 'switch', 'return'):
            continue
        G.add_node(fname)
        functions.append((fname, m.end()))  # body starts right after '{'

    # ── 2. Extract function body & find calls ─────────────────────────────────
    all_func_names = set(G.nodes)

    for i, (caller, body_start) in enumerate(functions):
        # Determine body end by brace counting
        depth = 1
        pos = body_start
        while pos < len(code) and depth > 0:
            if code[pos] == '{':
                depth += 1
            elif code[pos] == '}':
                depth -= 1
            pos += 1
        body = code[body_start:pos - 1]

        # Find calls: identifier immediately followed by '('
        call_pattern = re.compile(r'\b(\w+)\s*\(')
        for cm in call_pattern.finditer(body):
            callee = cm.group(1)
            if callee in all_func_names and callee != caller:
                G.add_edge(caller, callee)

    return G


def find_all_paths(G: nx.DiGraph, source: str, target: str):
    """Return all simple paths from source to target."""
    try:
        paths = list(nx.all_simple_paths(G, source=source, target=target))
        return paths
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []


def analyze(code: str, source: str, target: str) -> dict:
    G = extract_call_graph(code)
    nodes = list(G.nodes)
    edges = list(G.edges)

    reachable = False
    paths = []

    if source in G and target in G:
        paths = find_all_paths(G, source, target)
        reachable = len(paths) > 0
    elif source not in G:
        return {"error": f"함수 '{source}'를 소스 코드에서 찾을 수 없습니다."}
    elif target not in G:
        return {"error": f"함수 '{target}'를 소스 코드에서 찾을 수 없습니다."}

    return {
        "reachable": reachable,
        "paths": paths,
        "graph": G,
        "nodes": nodes,
        "edges": edges,
        "source": source,
        "target": target,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  VEX REPORT
# ══════════════════════════════════════════════════════════════════════════════

def build_vex_report(result: dict) -> dict:
    """Convert analysis result to a minimal VEX-style JSON report."""
    status = "affected" if result["reachable"] else "not_affected"
    justification = None if result["reachable"] else "vulnerable_code_not_in_execute_path"

    statements = []
    for i, path in enumerate(result["paths"]):
        statements.append({
            "vulnerability": {
                "id": f"CUSTOM-PATH-{i+1}",
                "name": f"Reachable path to {result['target']}",
            },
            "products": [{"id": "analyzed-binary"}],
            "status": status,
            "justification": justification,
            "impact_statement": " → ".join(path),
        })

    if not statements:
        statements.append({
            "vulnerability": {"id": "CUSTOM-PATH-1", "name": f"Path to {result['target']}"},
            "products": [{"id": "analyzed-binary"}],
            "status": status,
            "justification": justification,
            "impact_statement": f"No execution path found from {result['source']} to {result['target']}",
        })

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://example.com/vex/{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "author": "VulnPath Analyzer (MVP)",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "version": 1,
        "statements": statements,
        "metadata": {
            "source_function": result["source"],
            "target_function": result["target"],
            "total_functions": len(result["nodes"]),
            "total_edges": len(result["edges"]),
            "paths_found": len(result["paths"]),
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
#  PYVIS GRAPH
# ══════════════════════════════════════════════════════════════════════════════

def render_graph(result: dict) -> str:
    G: nx.DiGraph = result["graph"]
    source = result["source"]
    target = result["target"]
    paths = result["paths"]

    # Collect all nodes/edges on dangerous paths
    danger_nodes = set()
    danger_edges = set()
    for path in paths:
        for node in path:
            danger_nodes.add(node)
        for a, b in zip(path, path[1:]):
            danger_edges.add((a, b))

    net = Network(
        height="520px",
        width="100%",
        directed=True,
        bgcolor="#0d1117",
        font_color="#c9d1d9",
    )
    net.set_options("""
    {
      "nodes": {
        "shape": "box",
        "borderWidth": 1,
        "font": {"size": 14, "face": "Share Tech Mono, monospace"},
        "margin": 10
      },
      "edges": {
        "arrows": {"to": {"enabled": true, "scaleFactor": 0.8}},
        "smooth": {"type": "cubicBezier"}
      },
      "physics": {
        "barnesHut": {"gravitationalConstant": -8000, "springLength": 140},
        "stabilization": {"iterations": 200}
      },
      "interaction": {"hover": true, "navigationButtons": true}
    }
    """)

    for node in G.nodes:
        if node == target:
            color = "#f85149"; border = "#ff6b6b"; size = 26
        elif node == source:
            color = "#388bfd"; border = "#79c0ff"; size = 26
        elif node in danger_nodes:
            color = "#6e2a2a"; border = "#f85149"; size = 20
        else:
            color = "#161b22"; border = "#30363d"; size = 18

        net.add_node(
            node, label=node,
            color={"background": color, "border": border, "highlight": {"background": "#21262d", "border": "#f0883e"}},
            size=size,
            title=f"Function: {node}" + (" ⚠ TARGET" if node == target else "") + (" ▶ SOURCE" if node == source else ""),
        )

    for u, v in G.edges:
        if (u, v) in danger_edges:
            net.add_edge(u, v, color="#f85149", width=3, title="DANGER PATH")
        else:
            net.add_edge(u, v, color="#30363d", width=1.2)

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
    net.save_graph(tmp.name)
    with open(tmp.name, "r", encoding="utf-8") as f:
        html = f.read()
    os.unlink(tmp.name)
    return html


# ══════════════════════════════════════════════════════════════════════════════
#  SIDEBAR
# ══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("## 🔴 VulnPath")
    st.markdown("<small style='color:#8b949e;font-family:monospace'>Reachability Analyzer v0.1</small>", unsafe_allow_html=True)
    st.divider()

    st.markdown("### ⚙ 분석 설정")
    source_func = st.text_input("시작 함수 (Entry Point)", value="main", help="분석을 시작할 함수 이름")
    target_func = st.text_input("대상 함수 (취약 함수)", value="process_input", help="도달 가능성을 확인할 취약 함수")

    st.divider()
    st.markdown("### 🧪 샘플 코드")
    if st.button("📋 샘플 C 코드 불러오기", use_container_width=True):
        st.session_state["sample_loaded"] = True

    st.divider()
    st.markdown("""
<small style='color:#8b949e;'>
<b>지원 언어:</b> C / C++<br>
<b>분석 방식:</b> 정적 Call-Graph<br>
<b>출력 형식:</b> VEX JSON
</small>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN AREA
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("# 🔴 VulnPath Analyzer")
st.markdown("<p style='color:#8b949e;font-family:monospace;margin-top:-12px;'>소스 코드 취약점 도달 가능성 분석 엔진</p>", unsafe_allow_html=True)
st.divider()

default_code = SAMPLE_CODE if st.session_state.get("sample_loaded") else ""

code_input = st.text_area(
    "📄 C/C++ 소스 코드 입력",
    value=default_code,
    height=300,
    placeholder="분석할 C/C++ 소스 코드를 붙여넣으세요...",
    help="함수 정의와 호출 관계를 포함한 코드를 입력하세요.",
)

col_run, col_clear = st.columns([2, 1])
with col_run:
    run_btn = st.button("🔍 취약점 경로 분석 실행", use_container_width=True, type="primary")
with col_clear:
    if st.button("🗑 초기화", use_container_width=True):
        st.session_state["sample_loaded"] = False
        st.rerun()

# ── Run analysis ──────────────────────────────────────────────────────────────
if run_btn:
    if not code_input.strip():
        st.warning("소스 코드를 입력해주세요.")
    else:
        with st.spinner("🔬 Call-Graph 구성 중..."):
            result = analyze(code_input, source_func.strip(), target_func.strip())

        if "error" in result:
            st.error(f"❌ {result['error']}")
        else:
            st.session_state["result"] = result

# ── Display result ────────────────────────────────────────────────────────────
if "result" in st.session_state:
    result = st.session_state["result"]
    st.divider()

    # ── Summary cards ──────────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("🔵 총 함수 수", len(result["nodes"]))
    c2.metric("🔗 총 호출 관계", len(result["edges"]))
    c3.metric("⚠️ 위험 경로 수", len(result["paths"]))

    status_text = "🔴 REACHABLE" if result["reachable"] else "🟢 UNREACHABLE"
    c4.metric("판정", status_text)

    # ── Result card ────────────────────────────────────────────────────────
    if result["reachable"]:
        st.markdown(f"""
<div class="card card-danger">
  <span class="badge-danger">⚠ VULNERABLE — 취약 함수 도달 가능</span><br>
  <span class="badge-info">'{result['source']}' → '{result['target']}' 경로가 존재합니다. 공격자가 해당 경로를 통해 취약 함수에 접근할 수 있습니다.</span>
</div>
""", unsafe_allow_html=True)
    else:
        st.markdown(f"""
<div class="card card-safe">
  <span class="badge-safe">✔ SAFE — 취약 함수 도달 불가</span><br>
  <span class="badge-info">'{result['source']}' 에서 '{result['target']}' 까지의 실행 경로가 존재하지 않습니다.</span>
</div>
""", unsafe_allow_html=True)

    # ── Execution paths ────────────────────────────────────────────────────
    if result["paths"]:
        st.markdown("### 🛤 발견된 실행 경로")
        for i, path in enumerate(result["paths"]):
            steps = " → ".join([
                f"<span class='path-step'>{fn}</span>" for fn in path
            ])
            st.markdown(
                f"<div class='card'><b style='color:#e3b341;'>경로 {i+1}</b>&nbsp;&nbsp;{steps}</div>",
                unsafe_allow_html=True,
            )

    # ── Graph visualization ────────────────────────────────────────────────
    st.markdown("### 🕸 함수 Call-Graph 시각화")
    st.markdown(
        "<small style='color:#8b949e;'>🔵 시작 함수 &nbsp;|&nbsp; 🔴 취약 함수 &nbsp;|&nbsp; 🟥 위험 경로 노드 &nbsp;|&nbsp; ── 일반 호출 &nbsp;|&nbsp; <span style='color:#f85149'>── 위험 경로</span></small>",
        unsafe_allow_html=True,
    )
    with st.spinner("그래프 렌더링 중..."):
        graph_html = render_graph(result)
    st.components.v1.html(graph_html, height=540, scrolling=False)

    # ── Detected functions ─────────────────────────────────────────────────
    with st.expander("📋 감지된 함수 목록"):
        cols = st.columns(4)
        for i, fn in enumerate(sorted(result["nodes"])):
            cols[i % 4].markdown(f"`{fn}`")

    # ── VEX download ───────────────────────────────────────────────────────
    st.divider()
    st.markdown("### 📥 VEX 리포트 다운로드")
    vex = build_vex_report(result)
    vex_json = json.dumps(vex, indent=2, ensure_ascii=False)
    st.download_button(
        label="⬇ VEX JSON 다운로드",
        data=vex_json,
        file_name=f"vulnpath_vex_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json",
        use_container_width=True,
    )
    with st.expander("🔍 VEX JSON 미리보기"):
        st.code(vex_json, language="json")
