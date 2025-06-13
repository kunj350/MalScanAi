
import streamlit as st
from scanner import scan_virustotal, scan_gsb

st.set_page_config(page_title="MalScanAI", layout="centered")
st.title("🛡️ MalScanAI - Malicious URL Scanner")

url = st.text_input("🔗 Enter a URL to scan")

if st.button("🔍 Scan Now"):
    if not url.startswith("http"):
        st.warning("❗ URL must start with http:// or https://")
    else:
        st.info("🧪 Scanning with VirusTotal...")
        vt = scan_virustotal(url)
        st.json(vt)

        st.info("🧪 Scanning with Google Safe Browsing...")
        gsb = scan_gsb(url)

        if "matches" in gsb:
            st.error("🚨 Google Safe Browsing detected a threat!")
            st.json(gsb)
        else:
            st.success("✅ No threat found (Google Safe Browsing)")
