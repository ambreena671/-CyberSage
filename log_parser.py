"""
CyberSage - Log Parser Module
Handles parsing, normalization, validation, and structure extraction from CSV and TXT logs.
"""

import pandas as pd
import io
from typing import Tuple, List, Dict, Any

REQUIRED_COLUMNS = {'timestamp', 'event', 'user', 'ip'}

def parse_logs(file_data: Any, filename: str = "") -> Tuple[bool, pd.DataFrame, str]:
    """
    Parses CSV or TXT log content into a normalized pandas DataFrame.
    Returns: (success: bool, dataframe: pd.DataFrame, message: str)
    """
    try:
        if isinstance(file_data, pd.DataFrame):
            df = file_data.copy()
        elif isinstance(file_data, str):
            df = pd.read_csv(io.StringIO(file_data))
        elif hasattr(file_data, 'read'):
            content = file_data.read().decode('utf-8', errors='ignore')
            df = pd.read_csv(io.StringIO(content))
        else:
            return False, pd.DataFrame(), "Unsupported file payload format."

        # Normalize column names
        df.columns = df.columns.str.strip().str.lower()
        
        # Check required columns
        missing = REQUIRED_COLUMNS - set(df.columns)
        if missing:
            return False, pd.DataFrame(), f"Missing required columns in log file: {', '.join(missing)}"

        # Strip spaces from string values
        for col in ['event', 'user', 'ip']:
            df[col] = df[col].astype(str).str.strip()

        df['timestamp'] = df['timestamp'].astype(str).str.strip()
        
        if df.empty:
            return False, pd.DataFrame(), "The provided log dataset is empty."

        return True, df, f"Successfully parsed {len(df)} log records."

    except Exception as e:
        return False, pd.DataFrame(), f"Log parsing error: {str(e)}"

def extract_log_summary(df: pd.DataFrame) -> Dict[str, Any]:
    """Extracts high-level security metrics from parsed logs."""
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