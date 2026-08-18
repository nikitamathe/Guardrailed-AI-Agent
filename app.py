import os

import requests
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")

st.set_page_config(page_title="Guardrailed AI SOC", layout="wide")

st.title("Guardrailed AI SOC")

with st.form("soc_query"):
    user_input = st.text_area("Security query", placeholder="Investigate brute force attacks from 192.168.1.105")
    submitted = st.form_submit_button("Analyze")

if submitted and user_input.strip():
    try:
        response = requests.post(
            f"{API_BASE_URL}/api/v1/query",
            json={"query": user_input},
            timeout=60,
        )
        response.raise_for_status()
        payload = response.json()

        st.subheader("Agent response")
        st.write(payload.get("message", "No output returned."))

        if payload.get("tool_used"):
            st.info(f"Tool executed: {payload['tool_used']}")
            if payload.get("tool_output"):
                st.code(payload["tool_output"])
    except requests.RequestException as exc:
        st.error(f"Unable to reach SOC engine: {exc}")
