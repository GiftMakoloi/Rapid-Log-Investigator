import re
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Rapid Log Investigator", layout="wide")

st.title("Rapid Log Investigator")
st.caption("Lightweight threat hunting and automated log analysis for security analysts.")

# Helper to generate synthetic log data for testing
def generate_sample_logs():
    return """192.168.1.10 - - [15/Aug/2026:10:01:12 +0000] "GET /index.html HTTP/1.1" 200 1024 "Mozilla/5.0"
192.168.1.15 - - [15/Aug/2026:10:01:45 +0000] "GET /login.php HTTP/1.1" 200 2048 "Mozilla/5.0"
10.0.0.55 - - [15/Aug/2026:10:02:01 +0000] "POST /login.php HTTP/1.1" 401 512 "sqlmap/1.5.2"
10.0.0.55 - - [15/Aug/2026:10:02:03 +0000] "GET /admin.php?id=1%27%20OR%201=1-- HTTP/1.1" 500 404 "sqlmap/1.5.2"
10.0.0.55 - - [15/Aug/2026:10:02:05 +0000] "GET /etc/passwd HTTP/1.1" 404 280 "Nikto"
192.168.1.20 - - [15/Aug/2026:10:03:10 +0000] "GET /dashboard HTTP/1.1" 200 4096 "Mozilla/5.0"
10.0.0.88 - - [15/Aug/2026:10:04:12 +0000] "POST /login HTTP/1.1" 401 128 "Python-urllib/3.8"
10.0.0.88 - - [15/Aug/2026:10:04:13 +0000] "POST /login HTTP/1.1" 401 128 "Python-urllib/3.8"
10.0.0.88 - - [15/Aug/2026:10:04:14 +0000] "POST /login HTTP/1.1" 401 128 "Python-urllib/3.8"
10.0.0.88 - - [15/Aug/2026:10:04:15 +0000] "POST /login HTTP/1.1" 401 128 "Python-urllib/3.8"
"""

# Parser function for common web log format
def parse_logs(log_text):
    log_pattern = r'(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) \S+" (\d{3}) (\d+)'
    lines = log_text.strip().split("\n")
    data = []
    
    for line in lines:
        match = re.search(log_pattern, line)
        if match:
            ip, timestamp, method, path, status, size = match.groups()
            data.append({
                "IP Address": ip,
                "Timestamp": timestamp,
                "Method": method,
                "Path": path,
                "Status": int(status),
                "Size (Bytes)": int(size),
                "Raw Line": line
            })
    return pd.DataFrame(data)

# Sidebar ingestion options
st.sidebar.header("Log Source")
use_sample = st.sidebar.checkbox("Use Sample Log Dataset", value=True)
uploaded_file = st.sidebar.file_uploader("Upload Log File (.log, .txt)", type=["log", "txt"])

log_content = ""
if uploaded_file is not None:
    log_content = uploaded_file.getvalue().decode("utf-8")
elif use_sample:
    log_content = generate_sample_logs()

if not log_content:
    st.info("Please upload a log file or select the sample dataset to start threat hunting.")
else:
    df = parse_logs(log_content)
    
    if df.empty:
        st.error("Could not parse the log format. Ensure the log follows Common Log Format standards.")
    else:
        # Overview Metrics
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Requests", len(df))
        col2.metric("Unique IPs", df["IP Address"].nunique())
        col3.metric("Failed Requests (4xx/5xx)", len(df[df["Status"] >= 400]))
        col4.metric("High Risk Anomalies", len(df[df["Path"].str.contains(r"OR|passwd|admin|sqlmap|Nikto", case=False, regex=True)]))

        tab_overview, tab_threats, tab_analytics = st.tabs([
            "1. Log Explorer", 
            "2. Automated Threat Hunting", 
            "3. Visual Analytics"
        ])

        # TAB 1: LOG EXPLORER
        with tab_overview:
            st.header("Parsed Log Table")
            
            # Filtering options
            status_filter = st.multiselect("Filter by Status Code", options=sorted(df["Status"].unique()), default=sorted(df["Status"].unique()))
            filtered_df = df[df["Status"].isin(status_filter)]
            
            st.dataframe(filtered_df[["IP Address", "Timestamp", "Method", "Path", "Status", "Size (Bytes)"]], use_container_width=True)

        # TAB 2: THREAT HUNTING
        with tab_threats:
            st.header("Security Anomalies & Heuristic Detections")
            
            # Detection 1: SQL Injection & Path Traversal Patterns
            sqli_patterns = r"(%27|'|UNION|SELECT|OR|1=1|/etc/passwd)"
            sqli_matches = df[df["Path"].str.contains(sqli_patterns, case=False, regex=True)]
            
            with st.expander(f"Potential Injection & Traversal Attacks ({len(sqli_matches)} detected)", expanded=True):
                if not sqli_matches.empty:
                    st.warning("High severity web application attack signatures found in request parameters.")
                    st.dataframe(sqli_matches[["IP Address", "Path", "Status"]], use_container_width=True)
                    st.markdown("**Remediation:** Verify input validation and parameterized queries on endpoints.")
                else:
                    st.success("No common SQL injection or path traversal signatures detected.")

            # Detection 2: Automated Scanner User-Agents
            scanner_matches = df[df["Raw Line"].str.contains(r"(Nikto|sqlmap|nmap)", case=False, regex=True)]
            
            with st.expander(f"Automated Vulnerability Scanners ({len(scanner_matches)} detected)"):
                if not scanner_matches.empty:
                    st.warning("Traffic originating from known automated security scanners.")
                    st.dataframe(scanner_matches[["IP Address", "Path", "Raw Line"]], use_container_width=True)
                    st.markdown("**Remediation:** Block offending IPs at firewall level and implement rate limiting.")
                else:
                    st.success("No automated scanner user-agents detected.")

            # Detection 3: Brute Force Attempts (Spike in 401 status)
            failed_logins = df[df["Status"] == 401]["IP Address"].value_counts()
            brute_force_ips = failed_logins[failed_logins >= 3]
            
            with st.expander(f"Potential Brute Force Authentication ({len(brute_force_ips)} IPs flagged)"):
                if not brute_force_ips.empty:
                    st.warning("IP addresses with high frequency of failed authentication attempts:")
                    st.write(brute_force_ips)
                    st.markdown("**Remediation:** Enforce account lockout policies and multi-factor authentication.")
                else:
                    st.success("No brute force authentication patterns detected.")

        # TAB 3: VISUAL ANALYTICS
        with tab_analytics:
            st.header("Traffic Analytics")
            
            col_chart1, col_chart2 = st.columns(2)
            
            with col_chart1:
                st.subheader("Top IP Addresses by Request Count")
                ip_counts = df["IP Address"].value_counts()
                st.bar_chart(ip_counts)
                
            with col_chart2:
                st.subheader("HTTP Status Code Distribution")
                status_counts = df["Status"].value_counts()
                st.bar_chart(status_counts)
