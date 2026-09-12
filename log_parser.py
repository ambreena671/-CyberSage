"""
CyberSage - Log Parser Module
Handles parsing, normalization, validation, flexible column mapping, and structure extraction from CSV and TXT logs.
"""

import pandas as pd
import io
from typing import Tuple, List, Dict, Any

REQUIRED_COLUMNS = {'timestamp', 'event', 'user', 'ip'}

# Mapping dictionary for common log header variations across different SIEMs and datasets
COLUMN_MAPPING = {
    'time': 'timestamp',
    'datetime': 'timestamp',
    'date': 'timestamp',
    'action': 'event',
    'activity': 'event',
    'description': 'event',
    'log_event': 'event',
    'username': 'user',
    'userid': 'user',
    'account': 'user',
    'src_ip': 'ip',
    'srcip': 'ip',
    'ip_address': 'ip',
    'client_ip': 'ip',
    'source_ip': 'ip'
}

def parse_logs(file_data: Any, filename: str = "") -> Tuple[bool, pd.DataFrame, str]:
    """
    Parses CSV or TXT log content into a normalized pandas DataFrame.
    Automatically maps common column headers to expected schema (timestamp, event, user, ip).
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
            return False, pd.DataFrame(), "Unsupported file payload format."

        # Normalize column names (lowercase & strip spaces)
        df.columns = df.columns.astype(str).str.strip().str.lower()
        
        # Rename common header variations to expected standard headers
        df = df.rename(columns=COLUMN_MAPPING)
        
        # Check for required columns
        missing = REQUIRED_COLUMNS - set(df.columns)
        if missing:
            return False, pd.DataFrame(), f"Missing required columns in log file: {', '.join(missing)}"

        # Strip spaces from string values
        for col in ['event', 'user', 'ip', 'timestamp']:
            if col in df.columns:
                df[col] = df[col].astype(str).str.strip()
        
        if df.empty:
            return False, pd.DataFrame(), "The provided log dataset is empty."

        return True, df, f"Successfully parsed {len(df)} log records."

    except Exception as e:
        return False, pd.DataFrame(), f"Log parsing error: {str(e)}"

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
