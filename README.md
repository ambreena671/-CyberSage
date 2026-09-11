# 🛡️ CyberSage — Agentic AI Cyber Incident Investigator

CyberSage is an agentic AI-powered cybersecurity incident investigation dashboard. It converts raw, unstructured, or tabular security logs into correlated threat evidence, verified MITRE ATT&CK mappings, deterministic risk scores, visual attack flows, executive incident stories, and defensive response plans.

---

## 🌟 Key Features

1. **Deterministic Python Security Engine**: 
   - Normalizes and parses standard log entries (`CSV`/`TXT`).
   - Flags anomalous patterns and correlates sequential multi-event timelines.
   - Computes an explainable risk score (0–100) entirely in Python logic without LLM math hallucination.
2. **Verified MITRE ATT&CK Mapping**:
   - Maps observed suspicious indicators to verified MITRE technique IDs (e.g., `T1110`, `T1566`, `T1048`).
3. **Agentic AI Multi-Step Workflow**:
   - Executes sequential investigation steps using a state machine paradigm rather than single-prompt querying.
4. **Generative Intelligence Narratives**:
   - Synthesizes complex log timelines into cohesive executive attack stories using Google Gemini AI or Groq fallback.
5. **Interactive SOC Dashboard**:
   - Built with Streamlit, providing risk cards, dynamic visual attack flows, evidence timelines, and plain-text exportable incident reports.

---

## 🏗️ Architecture & Technical Workflow
