
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

# 👉 Check if it is malicious
if "data" in vt and "attributes" in vt["data"] and "last_analysis_stats" in vt["data"]["attributes"]:
    stats = vt["data"]["attributes"]["last_analysis_stats"]
    if stats["malicious"] > 0:
        st.error("⚠️ Link is DANGEROUS! VirusTotal found malicious content.")
    else:
        st.success("✅ Link looks safe (no malicious content found by VirusTotal).")
else:
    st.warning("⚠️ Unable to analyze the link properly. API response was unexpected.")


        st.info("🧪 Scanning with Google Safe Browsing...")
        gsb = scan_gsb(url)

        if "matches" in gsb:
            st.error("🚨 Google Safe Browsing detected a threat!")
            st.json(gsb)
        else:
            st.success("✅ No threat found (Google Safe Browsing)")
