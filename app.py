import os
import time
import random
import psutil
import requests
import streamlit as st
import pandas as pd

# --- API Configuration (decoupled engine microservice) ---
API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:8000")
_REQUEST_TIMEOUT = 60


def api_health() -> dict:
    """Query the engine's /health readiness endpoint."""
    try:
        resp = requests.get(f"{API_BASE_URL}/health", timeout=_REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        return {"status": "unreachable", "error": str(exc)}


def api_process(user_input: str, model: str = "llama3", require_approval: bool = True) -> dict:
    """POST a user prompt to the engine's /agent/process endpoint."""
    payload = {
        "user_input": user_input,
        "model_override": model,
        "dry_run": False,
        "require_approval": require_approval,
    }
    try:
        resp = requests.post(f"{API_BASE_URL}/agent/process", json=payload, timeout=_REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as exc:
        return {"status": "error", "message": f"Engine error: {resp.status_code}", "tool_used": None, "tool_output": None}
    except Exception as exc:
        return {"status": "error", "message": f"Engine unreachable: {exc}", "tool_used": None, "tool_output": None}


def api_approve(action_id: str, decision: str = "approve") -> dict:
    """Approve or reject a pending destructive tool action via /agent/approve."""
    try:
        resp = requests.post(
            f"{API_BASE_URL}/agent/approve",
            json={"action_id": action_id, "decision": decision},
            timeout=_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return {"ok": True, **resp.json()}
    except requests.exceptions.HTTPError:
        try:
            detail = resp.json().get("detail", f"HTTP {resp.status_code}")
        except Exception:
            detail = f"HTTP {resp.status_code}"
        return {"ok": False, "decision": decision, "action_id": action_id, "detail": detail}
    except Exception as exc:
        return {"ok": False, "decision": decision, "action_id": action_id, "detail": f"Engine unreachable: {exc}"}


# --- Streamlit Page Configuration ---
st.set_page_config(
    page_title="AI-Powered SOC Operations Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Dark SOC Custom CSS Styling
st.markdown("""
<style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #1e222d; padding: 12px; border-radius: 8px; border: 1px solid #2e364f; }
    .stAlert { border-radius: 8px; }
    div[data-testid="stSidebar"] { background-color: #161922; }
</style>
""", unsafe_allow_html=True)

# --- Initialize Engine Connection Status ---
@st.cache_resource
def init_agent_health():
    """Cache the engine /health response so the UI pings once per session."""
    return api_health()

engine_health = init_agent_health()
engine_online = engine_health.get("status") == "ok"

# Session State Store for Real-time Feeds
if "logs" not in st.session_state:
    st.session_state.logs = [
        {"timestamp": "2026-08-17 20:10:02", "level": "WARNING", "source": "sshd", "event": "Failed password for root from 192.168.1.105 port 22"},
        {"timestamp": "2026-08-17 20:10:05", "level": "WARNING", "source": "sshd", "event": "Failed password for root from 192.168.1.105 port 22"},
        {"timestamp": "2026-08-17 20:11:12", "level": "CRITICAL", "source": "nginx", "event": "Possible SQL Injection: 'UNION SELECT username, password FROM users'"},
        {"timestamp": "2026-08-17 20:12:00", "level": "INFO", "source": "systemd", "event": "Service nginx restarted via agent rule"},
    ]

if "guardrail_alerts" not in st.session_state:
    st.session_state.guardrail_alerts = [
        {"timestamp": "2026-08-17 20:05:11", "rule": "Malicious Command Injection", "payload": "restart nginx; rm -rf /", "action": "BLOCKED"},
    ]

if "banned_ips" not in st.session_state:
    st.session_state.banned_ips = [
        {"ip": "192.168.1.105", "reason": "Brute Force SSH Attack", "banned_at": "2026-08-17 20:10:10", "status": "ACTIVE"},
        {"ip": "10.0.4.88", "reason": "SQL Injection Attempt", "banned_at": "2026-08-17 19:42:01", "status": "ACTIVE"}
    ]

if "chat_history" not in st.session_state:
    st.session_state.chat_history = [
        {"role": "assistant", "content": "Hello Analyst Nikita. I am your SOC AI Assistant backed by Ollama, FAISS RAG, and Safety Guardrails. How can I assist with threat investigation?"}
    ]

# --- Sidebar: System Status & Ollama Config ---
with st.sidebar:
    st.title("🛡️ SOC Control Center")
    st.caption("AI-Powered SIEM / SOAR Platform")
    st.divider()

    st.subheader("🤖 Ollama LLM Settings")
    ollama_model = st.selectbox("Select Model", ["llama3", "llama3:8b", "qwen2.5-coder", "mistral"], index=0)
    st.success(f"Backend LLM: **{ollama_model}**")

    st.divider()
    st.subheader("🖥️ Hardware Telemetry")
    cpu_usage = psutil.cpu_percent(interval=0.5)
    ram_usage = psutil.virtual_memory().percent

    col_cpu, col_ram = st.columns(2)
    col_cpu.metric("CPU Load", f"{cpu_usage}%")
    col_ram.metric("RAM Usage", f"{ram_usage}%")

    st.progress(cpu_usage / 100)
    st.progress(ram_usage / 100)

    st.divider()
    if st.button("🔄 Trigger Simulated Attack Event", width="stretch"):
        new_ip = f"192.168.1.{random.randint(110, 250)}"
        st.session_state.logs.insert(0, {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "level": "CRITICAL",
            "source": "sshd",
            "event": f"Brute Force threshold exceeded from {new_ip}"
        })
        st.toast(f"New Critical Alert: {new_ip}", icon="🚨")
        st.rerun()

# --- Main Dashboard Banner ---
st.title("🚨 Security Operations Center (SOC) Dashboard")
st.caption("Real-Time Threat Intelligence, Deterministic Guardrails & SOAR Remediation")

# KPI Summary Cards
kpi1, kpi2, kpi3, kpi4 = st.columns(4)
kpi1.metric("Total Ingested Logs", len(st.session_state.logs), delta="+4 this session")
kpi2.metric("Guardrail Interceptions", len(st.session_state.guardrail_alerts), delta="100% Prevented")
kpi3.metric("Active Firewall Bans", len(st.session_state.banned_ips), delta="SOAR Active")
kpi4.metric("SOC Engine Status", "ONLINE" if engine_online else "OFFLINE", delta_color="normal")

st.divider()

# --- Main Section Tabs ---
tab_ops, tab_ai, tab_soar = st.tabs(["📊 Live SIEM & Guardrails", "💬 AI SOC Analyst (Ollama + RAG)", "⚙️ SOAR Firewall & Active Defense"])

# TAB 1: Live SIEM Logs & Guardrails
with tab_ops:
    col_logs, col_alerts = st.columns([3, 2])

    with col_logs:
        st.subheader("📜 Live Ingested System Logs (SIEM Stream)")
        df_logs = pd.DataFrame(st.session_state.logs)
        st.dataframe(
            df_logs,
            width="stretch",
            column_config={
                "level": st.column_config.TextColumn("Severity"),
                "event": st.column_config.TextColumn("Log Message", width="large")
            },
            hide_index=True
        )

    with col_alerts:
        st.subheader("🛡️ Real-Time Guardrail Interceptions")
        for alert in st.session_state.guardrail_alerts:
            with st.expander(f"❌ [{alert['action']}] {alert['rule']}", expanded=True):
                st.write(f"**Timestamp:** {alert['timestamp']}")
                st.code(alert['payload'], language="bash")
                st.caption("Prevented prompt injection or destructive command before execution.")

# TAB 2: Interactive AI SOC Analyst
with tab_ai:
    st.subheader("🤖 Natural Language Threat Query & Remediation")
    st.info("The agent processes queries through Safety Guardrails, queries FAISS log vectors, and executes tool actions.")

    # Render Chat History
    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # User Query Input Box
    if user_prompt := st.chat_input("Ask about suspicious IPs, system state, or request actions (e.g. 'Block IP 8.8.8.8')"):
        st.session_state.chat_history.append({"role": "user", "content": user_prompt})
        with st.chat_message("user"):
            st.markdown(user_prompt)

        with st.chat_message("assistant"):
            with st.spinner("Analyzing context via RAG & applying Guardrails..."):
                response = api_process(user_prompt, model=ollama_model, require_approval=True)

                if not engine_online:
                    st.error("🚨 **SOC Engine is OFFLINE.** Start it with `uvicorn api:app --port 8000`.")
                    ans_text = f"**Engine offline ({API_BASE_URL}).** Could not process request."
                    st.session_state.chat_history.append({"role": "assistant", "content": ans_text})
                elif response.get("status") == "blocked":
                    st.error(f"🚨 **Guardrail Blocked Input:** {response.get('message')}")
                    st.session_state.guardrail_alerts.insert(0, {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "rule": "Input Sanitization Filter",
                        "payload": user_prompt,
                        "action": "BLOCKED"
                    })
                    ans_text = f"**Blocked by Guardrail:** {response.get('message')}"
                    st.session_state.chat_history.append({"role": "assistant", "content": ans_text})

                elif response.get("status") == "pending_approval":
                    st.warning(f"🧾 **Action requires approval:** {response.get('message')}")
                    action_id = ""
                    raw_tool_output = response.get("tool_output")
                    if isinstance(raw_tool_output, dict):
                        action_id = str(raw_tool_output.get("action_id", ""))
                        st.json(raw_tool_output)
                    else:
                        st.code(str(raw_tool_output))
                        try:
                            import json
                            action_id = str(json.loads(raw_tool_output).get("action_id", ""))
                        except Exception:
                            action_id = ""
                    col_y, col_n = st.columns(2)
                    if col_y.button("✅ Approve"):
                        result = api_approve(action_id, "approve")
                        ans_text = f"Approved action. Result: {result}"
                    elif col_n.button("❌ Reject"):
                        result = api_approve(action_id, "reject")
                        ans_text = f"Action rejected. {result}"
                    else:
                        ans_text = f"Awaiting approval for {response.get('tool_used')}."
                    st.session_state.chat_history.append({"role": "assistant", "content": ans_text})

                else:
                    ans_text = response.get("message", "")
                    if response.get("status") == "tool_execution":
                        st.success(f"⚙️ **Tool Executed:** `{response.get('tool_used')}`")
                        st.write(response.get("tool_output"))
                        ans_text = f"Executed `{response.get('tool_used')}` successfully. Result: {response.get('tool_output')}"
                        if response.get("tool_used") == "block_ip":
                            st.session_state.banned_ips.insert(0, {
                                "ip": "8.8.8.8",
                                "reason": "AI Agent SOAR Action",
                                "banned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                                "status": "ACTIVE"
                            })
                    else:
                        st.markdown(ans_text)

                    st.session_state.chat_history.append({"role": "assistant", "content": ans_text})

# TAB 3: SOAR Firewall & Active Defense
with tab_soar:
    st.subheader("🔥 Active Firewall Blocklist (`iptables` / OS Network Rules)")
    df_bans = pd.DataFrame(st.session_state.banned_ips)
    st.dataframe(df_bans, width="stretch", hide_index=True)

    col_unban, col_manual = st.columns(2)
    with col_unban:
        ip_to_unban = st.text_input("Unban IP Address", placeholder="e.g. 192.168.1.105")
        if st.button("🔓 Revoke IP Ban"):
            st.session_state.banned_ips = [b for b in st.session_state.banned_ips if b["ip"] != ip_to_unban]
            st.success(f"Unbanned {ip_to_unban}")
            st.rerun()

    with col_manual:
        manual_ip = st.text_input("Manual IP Block", placeholder="e.g. 10.0.0.50")
        if st.button("🚫 Apply Firewall Drop Rule"):
            st.session_state.banned_ips.insert(0, {
                "ip": manual_ip,
                "reason": "Manual Analyst Override",
                "banned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "status": "ACTIVE"
            })
            st.success(f"Blocked {manual_ip}")
            st.rerun()