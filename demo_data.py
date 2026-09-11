"""
CyberSage - Demo Incident Data Loader
Provides synthetic security log datasets for instant demonstration without file uploads.
"""

import pandas as pd
import io

DEMO_SCENARIO_1 = """timestamp,event,user,ip
09:10,Failed Login,Ali,192.168.1.20
09:11,Failed Login,Ali,192.168.1.20
09:13,Successful Login,Ali,192.168.1.20
09:15,Admin Panel Access,Ali,192.168.1.20
09:18,Sensitive File Access,Ali,192.168.1.20
09:20,Large Data Transfer,Ali,192.168.1.20"""

DEMO_SCENARIO_2 = """timestamp,event,user,ip
09:00,Suspicious Email,User01,mail
09:03,Malicious Link Click,User01,web
09:05,Login Attempt,User01,10.0.0.5
09:06,Successful Login,User01,10.0.0.5
09:10,Account Settings Changed,User01,10.0.0.5"""

DEMO_SCENARIO_3 = """timestamp,event,user,ip
14:00,Successful Login,User02,10.0.0.10
14:05,Database Access,User02,10.0.0.10
14:07,Multiple Sensitive Files Accessed,User02,10.0.0.10
14:10,Large Data Transfer,User02,10.0.0.10"""

def get_demo_data(scenario_id: int) -> pd.DataFrame:
    """Returns a pandas DataFrame corresponding to the requested demo scenario."""
    if scenario_id == 1:
        return pd.read_csv(io.StringIO(DEMO_SCENARIO_1))
    elif scenario_id == 2:
        return pd.read_csv(io.StringIO(DEMO_SCENARIO_3 if scenario_id == 3 else DEMO_SCENARIO_2))
    elif scenario_id == 3:
        return pd.read_csv(io.StringIO(DEMO_SCENARIO_3))
    else:
        return pd.read_csv(io.StringIO(DEMO_SCENARIO_1))