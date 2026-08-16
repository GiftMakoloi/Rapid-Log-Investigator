# Rapid Log Investigator

A lightweight, browser-based log parser and visualization tool built with Streamlit and Pandas. Designed for small-to-medium enterprises (SMEs), SOC analysts, and digital forensics learners to detect security anomalies without full SIEM infrastructure.

## Overview

Small businesses and security learners often lack access to enterprise SIEM platforms when investigating suspected incidents. Facing raw server or authentication logs containing thousands of entries can slow down incident response.

The Rapid Log Investigator acts as a fast, local threat-hunting tool. Upload raw web or authentication logs to instantly highlight brute-force attempts, web application attack signatures, and traffic anomalies through visual analytics.

## Key Features

*   Drag-and-Drop Parsing: Supports `.log`, `.txt`, and `.csv` web and server access logs.
*   Automated Threat Identification: Uses regex-based heuristic detection to flag SQL injection patterns, automated scanners (e.g., Nikto, SQLmap), and brute-force authentication spikes.
*   Log Visualizations: Built-in charts displaying request distributions over time, HTTP status code spreads, and top remote IP addresses.
*   Built-in Sample Dataset: Includes a synthetic attack log generator so users can practice threat hunting immediately without uploading external files.

## Tech Stack

*   Python
*   Streamlit
*   Pandas

## Quickstart

1. Clone the repository:
   git clone https://github.com/yourusername/rapid-log-investigator.git
   cd rapid-log-investigator

2. Install dependencies:
   pip install -r requirements.txt

3. Run the application:
   streamlit run app.py

## License
MIT License
