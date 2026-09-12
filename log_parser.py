"""
CyberSage - Log Parser Module
Handles parsing, normalization, validation, flexible column mapping, and safe fallback extractions.
"""

import pandas as pd
import io
from typing import Tuple, Dict, Any

# Target schema expected by downstream correlation & risk engines
REQUIRED_COLUMNS = {'timestamp', 'event', 'user', 'ip'}

# Mapping dictionary for common log header variations across different SIEMs and datasets
COLUMN_MAPPING = {
    'time': 'timestamp',
    'datetime': 'timestamp',
    'date': 'timestamp',
    'timestamp_utc': 'timestamp',
    'action': 'event',
    'activity': 'event',
    'description': 'event',
    'log_event': 'event',
    'message': 'event',
    'username': 'user',
    'userid': 'user',
    'account': 'user',
    'src_ip': 'ip',
    'srcip': 'ip',
    'ip_address': 'ip',
    'client_ip': 'ip',
    'source_ip': 'ip',
    'host': 'ip'
}

def parse_logs(file_data: Any, filename: str = "") -> Tuple[bool, pd.DataFrame, str]:
    """
    Parses CSV or TXT log content into a normalized pandas DataFrame.
    If required columns are missing, it fills them gracefully with default values
    and returns a informative warning message rather than halting investigation.
    
    Returns: (success: bool, dataframe: pd.DataFrame, message: str)
    """
    try:
        if isinstance(file_data, pd.DataFrame):
            df = file_data.copy()
        elif isinstance(file_data, str):
            df = pd.read_csv(io.StringIO(file_data))
        elif hasattr(file_data, 'read'):
            content = file_data.read()
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='ignore')
            df = pd.read_csv(io.StringIO(content))
        else:
            return False, pd.DataFrame(), "Invalid file upload format. Please upload a valid CSV or TXT file."

        if df.empty:
            return False, pd.DataFrame(), "The uploaded dataset is empty. Please provide a file with log entries."

        # Normalize column names (lowercase & strip whitespace)
        df.columns = df.columns.astype(str).str.strip().str.lower()
        
        # Rename common header variations automatically
        df = df.rename(columns=COLUMN_MAPPING)
        
        # Detect missing essential columns
        missing = REQUIRED_COLUMNS - set(df.columns)
        warning_msg = ""

        # Auto-heal missing columns with safe defaults instead of crashing
        if missing:
            warning_msg = f"⚠️ Note: Missing columns ({', '.join(missing)}) were auto-filled with default placeholders.\n"
            
            if 'timestamp' in missing:
                df['timestamp'] = [f"2026-09-12 10:00:{i:02d}" for i in range(len(df))]
            if 'event' in missing:
                # Try to salvage from any text column or set default
                text_cols = df.select_dtypes(include=['object']).columns
                if len(text_cols) > 0:
                    df['event'] = df[text_cols[0]]
                else:
                    df['event'] = "Unclassified Security Event"
            if 'user' in missing:
                df['user'] = "Unknown_User"
            if 'ip' in missing:
                df['ip'] = "0.0.0.0"

        # Strip extra spaces from string fields
        for col in ['event', 'user', 'ip', 'timestamp']:
            df[col] = df[col].astype(str).str.strip()

        success_msg = f"Successfully processed {len(df)} records. {warning_msg}".strip()
        return True, df, success_msg

    except Exception as e:
        # Negative user-friendly response without crashing Streamlit
        return False, pd.DataFrame(), f"Unable to parse log file structure: {str(e)}. Please verify CSV formatting."

def extract_log_summary(df: pd.DataFrame) -> Dict[str, Any]:
    """Extracts high-level security metrics from parsed logs."""
    if df.empty:
        return {
            "total_events": 0,
            "unique_users": 0,
            "users_list": [],
            "unique_ips": 0,
            "ips_list": [],
            "event_types": {},
            "timeline_start": "N/A",
            "timeline_end": "N/A"
        }
        
    return {
        "total_events": len(df),
        "unique_users": df['user'].nunique(),
        "users_list": df['user'].unique().tolist(),
        "unique_ips": df['ip'].nunique(),
        "ips_list": df['ip'].unique().tolist(),
        "event_types": df['event'].value_counts().to_dict(),
        "timeline_start": df['timestamp'].iloc[0] if not df.empty else "N/A",
        "timeline_end": df['timestamp'].iloc[-1] if not df.empty else "N/A"
    }
