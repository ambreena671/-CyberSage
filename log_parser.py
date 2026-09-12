"""
Universal CyberSage Log Parser
Dynamically detects, maps, and normalizes ANY security dataset (Kaggle, SIEM, Firewall, Auth Logs).
"""

import pandas as pd
import datetime

# Prioritized target aliases (exact matches checked before partial substring matches)
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

def parse_logs(file_or_path):
    """
    Parses and normalizes any log file into standard CyberSage schema:
    [timestamp, event, user, ip]
    """
    try:
        # 1. Load Data
        if hasattr(file_or_path, 'read'):
            file_or_path.seek(0)
            df = pd.read_csv(file_or_path)
        elif isinstance(file_or_path, pd.DataFrame):
            df = file_or_path.copy()
        else:
            df = pd.read_csv(file_or_path)

        if df.empty:
            return False, df, "The uploaded dataset is empty."

        # Clean Column Headers
        raw_cols = [str(col).strip() for col in df.columns]
        clean_cols = [c.lower().replace(' ', '_').replace('-', '_') for c in raw_cols]
        df.columns = clean_cols

        mapped_cols = {}

        # 2. Prioritized Dynamic Column Mapping
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

        warnings = []
        
        # 3. Normalization & Context Aggregation
        
        # Timestamp Normalization
        if 'timestamp' in mapped_cols:
            df['timestamp'] = df[mapped_cols['timestamp']].astype(str)
        else:
            df['timestamp'] = [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") for _ in range(len(df))]
            warnings.append("timestamps auto-filled")

        # Event / Activity Label Normalization
        # If a explicit event column exists, use it; otherwise, concatenate text columns to preserve threat context
        string_cols = df.select_dtypes(include=['object', 'category']).columns.tolist()
        if 'event' in mapped_cols and mapped_cols['event'] in df.columns:
            primary_event = df[mapped_cols['event']].astype(str)
            # If primary event is mostly generic/numeric, combine with other text fields for richer context
            if len(string_cols) > 1:
                other_text = df[string_cols].astype(str).agg(' | '.join, axis=1)
                df['event'] = primary_event + " | " + other_text
            else:
                df['event'] = primary_event
        elif string_cols:
            df['event'] = df[string_cols].astype(str).agg(' | '.join, axis=1)
            warnings.append("event constructed from text features")
        else:
            df['event'] = "Suspicious Security Telemetry Record"
            warnings.append("default event category applied")

        # User Normalization
        if 'user' in mapped_cols:
            df['user'] = df[mapped_cols['user']].astype(str)
        else:
            df['user'] = "system_user"
            warnings.append("default user assigned")

        # IP Normalization
        if 'ip' in mapped_cols:
            df['ip'] = df[mapped_cols['ip']].astype(str)
        else:
            df['ip'] = "127.0.0.1"
            warnings.append("default local IP assigned")

        final_df = df[['timestamp', 'event', 'user', 'ip']].copy()

        if warnings:
            msg = f"Successfully parsed {len(final_df)} records. Note: {', '.join(warnings)}."
        else:
            msg = f"Successfully mapped columns from dataset across {len(final_df)} records."

        return True, final_df, msg

    except Exception as e:
        return False, pd.DataFrame(), f"Failed to parse log file: {str(e)}"


def extract_log_summary(df):
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
        "total_events": len(df),
        "unique_users": df['user'].unique().tolist() if 'user' in df.columns else [],
        "unique_ips": df['ip'].unique().tolist() if 'ip' in df.columns else [],
        "sample_events": df.head(10).to_dict(orient='records') if not df.empty else []
    }
