"""
Universal CyberSage Log Parser
Dynamically detects, maps, and normalizes ANY security dataset (Kaggle, SIEM, Firewall, Auth Logs).
"""

import pandas as pd
import datetime
from typing import Dict, Any, Union, IO

# Prioritized target aliases
ALIASES = {
    'timestamp': [
        'timestamp', 'time', 'datetime', 'date', 'date_time', 'event_time', 
        'timestamp_utc', 'start_time', 'flow_start', 'created_at', 'record_time'
    ],
    'event': [
        'label', 'attack', 'attack_type', 'attack_category', 'event', 'action', 
        'activity', 'description', 'log_event', 'message', 'action_taken', 
        'category', 'alert_description', 'payload_data', 'event_type', 'signature', 
        'threat_level', 'status', 'protocol', 'info', 'class'
    ],
    'user': [
        'user', 'username', 'userid', 'account', 'user_information', 'src_user', 
        'source_user', 'identity', 'dst_user', 'login', 'account_name', 'email'
    ],
    'ip': [
        'src_ip', 'source_ip', 'ip', 'srcip', 'ip_address', 'client_ip', 
        'source_ip_address', 'host', 'src_host', 'source', 'dst_ip', 'destination_ip', 'origin'
    ]
}


def parse_logs(file_or_path: Union[str, IO, pd.DataFrame]) -> pd.DataFrame:
    """
    Parses and normalizes any log dataset into standard CyberSage schema:
    [timestamp, event, user, ip]
    """
    fallback_df = pd.DataFrame(columns=['timestamp', 'event', 'user', 'ip'])

    if file_or_path is None:
        return fallback_df

    try:
        # 1. Load Data
        if isinstance(file_or_path, pd.DataFrame):
            df = file_or_path.copy()
        elif hasattr(file_or_path, 'read'):
            if hasattr(file_or_path, 'seek'):
                file_or_path.seek(0)
            df = pd.read_csv(file_or_path)
        else:
            df = pd.read_csv(file_or_path)

        if df.empty:
            return fallback_df

        # Clean Column Headers
        raw_cols = [str(col).strip() for col in df.columns]
        clean_cols = [c.lower().replace(' ', '_').replace('-', '_') for c in raw_cols]
        df.columns = clean_cols

        mapped_cols = {}

        # 2. Dynamic Column Mapping
        for target, keywords in ALIASES.items():
            # Pass A: Exact Match
            for kw in keywords:
                if kw in df.columns:
                    mapped_cols[target] = kw
                    break
            
            # Pass B: Substring Match if Exact Match Fails
            if target not in mapped_cols:
                for kw in keywords:
                    matched = [c for c in df.columns if kw in c]
                    if matched:
                        mapped_cols[target] = matched[0]
                        break

        # 3. Normalization
        
        # Timestamp Normalization
        if 'timestamp' in mapped_cols:
            df['timestamp'] = df[mapped_cols['timestamp']].astype(str)
        else:
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            df['timestamp'] = now_str

        # Event Normalization
        if 'event' in mapped_cols and mapped_cols['event'] in df.columns:
            df['event'] = df[mapped_cols['event']].astype(str)
        else:
            string_cols = df.select_dtypes(include=['object', 'category']).columns.tolist()
            if string_cols:
                df['event'] = df[string_cols].astype(str).agg(' | '.join, axis=1)
            else:
                df['event'] = "Security Telemetry Event"

        # User Normalization
        if 'user' in mapped_cols:
            df['user'] = df[mapped_cols['user']].astype(str)
        else:
            df['user'] = "system_user"

        # IP Normalization
        if 'ip' in mapped_cols:
            df['ip'] = df[mapped_cols['ip']].astype(str)
        else:
            df['ip'] = "127.0.0.1"

        # Fill missing values
        final_df = df[['timestamp', 'event', 'user', 'ip']].copy()
        final_df = final_df.fillna("unknown")

        return final_df

    except Exception:
        return fallback_df


def extract_log_summary(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Extracts summary telemetry from normalized DataFrame for agent processing.
    """
    if df is None or df.empty:
        return {
            "total_events": 0,
            "unique_users": [],
            "unique_ips": [],
            "sample_events": []
        }

    return {
        "total_events": int(len(df)),
        "unique_users": df['user'].dropna().unique().tolist() if 'user' in df.columns else [],
        "unique_ips": df['ip'].dropna().unique().tolist() if 'ip' in df.columns else [],
        "sample_events": df.head(10).to_dict(orient='records') if not df.empty else []
    }
