"""
Universal CyberSage Log Parser
Dynamically detects, maps, and normalizes ANY security dataset (Kaggle, SIEM, Firewall, Auth Logs).
"""

import pandas as pd
import datetime

# Comprehensive Alias Dictionary covering Kaggle, AWS, Splunk, Elastic, & CIC Datasets
ALIASES = {
    'timestamp': [
        'timestamp', 'time', 'datetime', 'date', 'date_time', 'event_time', 
        'timestamp_utc', 'start_time', 'flow_start', 'created_at', 'record_time'
    ],
    'event': [
        'event', 'action', 'activity', 'description', 'log_event', 'message', 
        'attack_type', 'label', 'action_taken', 'category', 'alert_description', 
        'payload_data', 'event_type', 'signature', 'threat_level', 'status', 'protocol'
    ],
    'user': [
        'user', 'username', 'userid', 'account', 'user_information', 'src_user', 
        'source_user', 'identity', 'dst_user', 'login', 'account_name', 'email'
    ],
    'ip': [
        'ip', 'src_ip', 'srcip', 'ip_address', 'client_ip', 'source_ip', 
        'source_ip_address', 'host', 'src_host', 'source', 'dst_ip', 'destination_ip', 'origin'
    ]
}

def parse_logs(file_or_path):
    """
    Parses and normalizes any log file into the standard CyberSage format:
    [timestamp, event, user, ip]
    """
    try:
        # Load File
        if hasattr(file_or_path, 'read'):
            file_or_path.seek(0)
            df = pd.read_csv(file_or_path)
        elif isinstance(file_or_path, pd.DataFrame):
            df = file_or_path.copy()
        else:
            df = pd.read_csv(file_or_path)

        if df.empty:
            return False, df, "The uploaded dataset is empty."

        # Clean Column Headers (lowercase and stripped)
        original_cols = list(df.columns)
        df.columns = [str(col).strip().lower().replace(' ', '_').replace('-', '_') for col in df.columns]

        # Dynamic Mapping Engine
        mapped_cols = {}
        for target, keywords in ALIASES.items():
            for kw in keywords:
                matched = [c for c in df.columns if kw in c]
                if matched:
                    mapped_cols[target] = matched[0]
                    break

        # Fallback & Synthesis Strategy for Missing Target Columns
        warnings = []
        
        # 1. Timestamp Fallback
        if 'timestamp' in mapped_cols:
            df['timestamp'] = df[mapped_cols['timestamp']]
        else:
            df['timestamp'] = [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") for _ in range(len(df))]
            warnings.append("timestamps were generated automatically")

        # 2. Event Fallback (Synthesizes textual context from non-standard columns)
        if 'event' in mapped_cols:
            df['event'] = df[mapped_cols['event']].astype(str)
        else:
            # Aggregate string columns into a single event summary string
            string_cols = df.select_dtypes(include=['object']).columns.tolist()
            if string_cols:
                df['event'] = df[string_cols].astype(str).agg(' | '.join, axis=1)
                warnings.append("event activity was constructed from available text fields")
            else:
                df['event'] = "System Activity Recorded"
                warnings.append("default event category applied")

        # 3. User Fallback
        if 'user' in mapped_cols:
            df['user'] = df[mapped_cols['user']].astype(str)
        else:
            df['user'] = "system_user"
            warnings.append("default user assigned")

        # 4. IP Fallback
        if 'ip' in mapped_cols:
            df['ip'] = df[mapped_cols['ip']].astype(str)
        else:
            df['ip'] = "127.0.0.1"
            warnings.append("default local IP assigned")

        # Keep normalized schema
        final_df = df[['timestamp', 'event', 'user', 'ip']].copy()

        # Format Warning Message
        if warnings:
            msg = f"Successfully parsed {len(final_df)} records. Note: {', '.join(warnings)}."
        else:
            msg = f"Successfully mapped all columns across {len(final_df)} records."

        return True, final_df, msg

    except Exception as e:
        return False, pd.DataFrame(), f"Failed to parse log file: {str(e)}"
