"""
CyberSage - Log Parser Module
Handles parsing CSV/TXT files and generating summary statistics.
"""

import pandas as pd
from typing import Dict, Any, Union, Tuple

def parse_logs(file_or_path: Union[str, Any]) -> pd.DataFrame:
    """Parses uploaded file objects or file paths into a structured DataFrame."""
    try:
        if isinstance(file_or_path, pd.DataFrame):
            return file_or_path

        df = pd.read_csv(file_or_path)
        
        # Standardize column names
        df.columns = [str(col).strip().lower() for col in df.columns]
        
        # Rename common aliases
        col_map = {
            'time': 'timestamp',
            'date': 'timestamp',
            'username': 'user',
            'src_ip': 'ip',
            'source_ip': 'ip',
            'ip_address': 'ip',
            'action': 'event',
            'activity': 'event'
        }
        df.rename(columns=col_map, inplace=True)
        
        # Ensure required columns exist
        for req_col in ['timestamp', 'event', 'user', 'ip']:
            if req_col not in df.columns:
                df[req_col] = "Unknown"
                
        return df
    except Exception as e:
        print(f"Parsing error: {e}")
        return pd.DataFrame()


def extract_log_summary(df: pd.DataFrame) -> Dict[str, Any]:
    """Extracts high-level summary metadata from parsed logs."""
    if df.empty:
        return {
            "total_events": 0,
            "unique_users": 0,
            "unique_ips": 0,
            "start_time": "N/A",
            "end_time": "N/A"
        }

    return {
        "total_events": len(df),
        "unique_users": int(df['user'].nunique()) if 'user' in df.columns else 0,
        "unique_ips": int(df['ip'].nunique()) if 'ip' in df.columns else 0,
        "start_time": str(df['timestamp'].iloc[0]) if 'timestamp' in df.columns and not df.empty else "N/A",
        "end_time": str(df['timestamp'].iloc[-1]) if 'timestamp' in df.columns and not df.empty else "N/A"
    }
