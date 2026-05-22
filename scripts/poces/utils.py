import requests
import os
import sys
import time
from typing import Dict, List, Tuple, Optional, Any

def make_request_with_trigger(url, method='GET', data=None, params=None, headers=None, cookies=None, timeout=30, **kwargs):
    """
    Send HTTP request and automatically add XDEBUG_TRIGGER to cookie
    
    Args:
        url (str): Request URL
        method (str): HTTP method ('GET', 'POST', 'PUT', 'DELETE', etc.)
        data (dict/str): POST data
        params (dict): URL parameters
        headers (dict): HTTP headers
        cookies (dict): Cookies
        timeout (int): Timeout duration
        **kwargs: Other requests parameters
    
    Returns:
        requests.Response: Response object
    """
    # Ensure cookies is a dictionary
    if cookies is None:
        cookies = {}
    elif isinstance(cookies, str):
        # If cookies is a string format, parse it
        cookie_dict = {}
        for item in cookies.split(';'):
            if '=' in item:
                key, value = item.strip().split('=', 1)
                cookie_dict[key] = value
        cookies = cookie_dict
    
    # Add XDEBUG_TRIGGER to cookies
    cookies['XDEBUG_TRIGGER'] = '1'
    
    # If no headers provided, create an empty dictionary
    if headers is None:
        headers = {}
    
    # Add common headers
    if 'User-Agent' not in headers:
        headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    
    try:
        # Send request
        response = requests.request(
            method=method.upper(),
            url=url,
            data=data,
            params=params,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            **kwargs
        )
        return response
    except Exception as e:
        print(f"Error making request to {url}: {str(e)}")
        raise


def make_get_request_with_trigger(url, params=None, **kwargs):
    """
    Send GET request and automatically add XDEBUG_TRIGGER
    
    Args:
        url (str): Request URL
        params (dict): URL parameters
        **kwargs: Other parameters
    
    Returns:
        requests.Response: Response object
    """
    return make_request_with_trigger(url, method='GET', params=params, **kwargs)


def make_post_request_with_trigger(url, data=None, **kwargs):
    """
    Send POST request and automatically add XDEBUG_TRIGGER
    
    Args:
        url (str): Request URL
        data (dict/str): POST data
        **kwargs: Other parameters
    
    Returns:
        requests.Response: Response object
    """
    return make_request_with_trigger(url, method='POST', data=data, **kwargs)


def save_response_to_crash_file(response):
    """
    Save HTTP response content to /tmp/crash.rsp file for pre-patch phase
    
    Args:
        response: requests.Response object
    
    Returns:
        str: Path to the saved file
    """
    crash_file = '/tmp/crash.rsp'
    
    # Remove existing file if it exists
    if os.path.exists(crash_file):
        os.unlink(crash_file)
    
    try:
        with open(crash_file, 'w') as f:
            f.write(response.text)

        print(f"[UTILS] Response saved to {crash_file}")
        return crash_file
    except Exception as e:
        print(f"[UTILS] Error saving response to {crash_file}: {e}")
        return None


def save_request_to_crash_file(url, method='GET', params=None, data=None):
    """
    Save HTTP request parameters to /tmp/crash.req file
    
    Args:
        url (str): Request URL
        method (str): HTTP method
        params (dict): URL parameters for GET requests
        data (dict): POST data for POST requests
    
    Returns:
        str: Path to the saved file
    """
    crash_file = '/tmp/crash.req'
    
    # Remove existing file if it exists
    if os.path.exists(crash_file):
        os.unlink(crash_file)
    
    try:
        with open(crash_file, 'w') as f:
            if method.upper() == 'GET' and params:
                # Convert params dict to URL query string
                import urllib.parse
                query_string = urllib.parse.urlencode(params)
                f.write(query_string)
            elif method.upper() == 'POST' and data:
                # Convert data dict to form data string
                import urllib.parse
                if isinstance(data, dict):
                    form_data = urllib.parse.urlencode(data)
                    f.write(form_data)
                else:
                    # If data is already a string, save it directly
                    f.write(str(data))
            else:
                # No parameters to save
                f.write("")

        print(f"[UTILS] Request parameters saved to {crash_file}")
        return crash_file
    except Exception as e:
        print(f"[UTILS] Error saving request to {crash_file}: {e}")
        return None
        

class VulnerabilityIndicator:
    """Base class for vulnerability indicators"""
    
    def __init__(self, patterns: List[str], name: str = ""):
        self.patterns = patterns
        self.name = name or "Generic"
    
    def check(self, response_text: str) -> Tuple[bool, str]:
        """
        Check if vulnerability indicators are present in response text
        
        Args:
            response_text (str): HTTP response text to check
            
        Returns:
            tuple: (found: bool, matched_pattern: str)
        """
        for pattern in self.patterns:
            if pattern.lower() in response_text.lower():
                return True, pattern
        return False, ""
    
    def find_complete_message(self, response_text: str, pattern: str) -> str:
        """
        Find the complete sentence/line containing the pattern
        
        Args:
            response_text (str): Response text to search
            pattern (str): Pattern that was matched
            
        Returns:
            str: Complete message containing the pattern
        """
        lines = response_text.split('\n')
        for line in lines:
            if pattern.lower() in line.lower():
                return line.strip()
        return pattern


class SQLiIndicator(VulnerabilityIndicator):
    """SQL injection vulnerability indicators"""
    
    def __init__(self):
        patterns = [
            'You have an error i',
            'syntax error',
            'mysql error'
        ]
        super().__init__(patterns, "SQL Injection")
    
    def check(self, response_text: str) -> Tuple[bool, str]:
        """
        Check if vulnerability indicators are present in response text or log file
        
        Args:
            response_text (str): HTTP response text to check
            
        Returns:
            tuple: (found: bool, matched_pattern: str)
        """
        # First check response text using parent method
        found, pattern = super().check(response_text)
        if found:
            return True, pattern
        
        # Check for SQL injection log file
        sqli_log_path = '/tmp/sqli.log'
        try:
            if os.path.exists(sqli_log_path) and os.path.getsize(sqli_log_path) > 0:
                print(f"[SQLi] Found non-empty SQL injection log file: {sqli_log_path}")
                with open(sqli_log_path, 'r') as f:
                    log_content = f.read()
                print(f"[SQLi] Log content: {log_content[:200]}...")  # Show first 200 chars
                print(f"[SQLi] Removed SQL injection log file: {sqli_log_path}")
                
                return True, "SQL injection detected via log file"
        except Exception as e:
            print(f"[SQLi] Error checking SQL injection log file: {e}")
        
        return False, ""


class XSSIndicator(VulnerabilityIndicator):
    """XSS vulnerability indicators"""
    
    def __init__(self):
        patterns = [
            '<script>alert(290363',
            'javascript:alert(290363',
            'onload=alert(290363)>',
            'onerror=alert(290363)>',
            'onmouseover=alert(290363)>',
            'onclick=alert(290363)>',
            '<img src=x onerror=alert(290363',
            'onclick="alert(290363)">',
            'onload="alert(290363)">',
            'onerror="alert(290363)">',
            'onmouseover="alert(290363)">',

        ]
        super().__init__(patterns, "XSS")

class CommandInjectionIndicator(VulnerabilityIndicator):
    """Command injection vulnerability indicators"""
    
    def __init__(self):
        patterns = [
            # Common command injection test patterns
            'COMMAND_INJECTION_TEST',  # custom test marker
        ]
        super().__init__(patterns, "Command Injection")
    
    def check(self, response_text: str) -> Tuple[bool, str]:
        """
        Check if vulnerability indicators are present in response text or log file
        
        Args:
            response_text (str): HTTP response text to check
            
        Returns:
            tuple: (found: bool, matched_pattern: str)
        """
        # First check response text using parent method
        found, pattern = super().check(response_text)
        if found:
            return True, pattern
        
        # Check for command injection log file
        cmdi_log_path = '/tmp/cmdi.log'
        try:
            if os.path.exists(cmdi_log_path) and os.path.getsize(cmdi_log_path) > 0:
                print(f"[CMDI] Found non-empty command injection log file: {cmdi_log_path}")
                with open(cmdi_log_path, 'r') as f:
                    log_content = f.read()
                print(f"[CMDI] Log content: {log_content[:200]}...")  # Show first 200 chars
                print(f"[CMDI] Removed command injection log file: {cmdi_log_path}")
                
                return True, "Command injection detected via log file"
        except Exception as e:
            print(f"[CMDI] Error checking command injection log file: {e}")
        
        return False, ""


class StandardPOCRunner:
    """Standardized POC runner that handles common POC patterns"""
    
    def __init__(self, cve_id: str, app_name: str, vuln_type: str):
        self.cve_id = cve_id
        self.app_name = app_name
        self.vuln_type = vuln_type
        self.use_trigger = os.environ.get('USE_XDEBUG_TRIGGER', 'true').lower() == 'true'
        
        # Select appropriate vulnerability indicator
        self.indicator = self._get_vulnerability_indicator()
    
    def _get_vulnerability_indicator(self) -> VulnerabilityIndicator:
        """Get appropriate vulnerability indicator based on type"""
        vuln_type_lower = self.vuln_type.lower()
        if 'sql' in vuln_type_lower:
            return SQLiIndicator()
        elif 'command' in vuln_type_lower:
            return CommandInjectionIndicator()
        elif 'code' in vuln_type_lower:
            return CommandInjectionIndicator()
        elif 'cmd' in vuln_type_lower:
            return CommandInjectionIndicator()
        elif 'rce' in vuln_type_lower:
            return CommandInjectionIndicator()
        elif 'xss' in vuln_type_lower:
            return XSSIndicator()
        elif 'cross' in vuln_type_lower:
            return XSSIndicator()
        else:
            # Generic indicators for other vulnerability types
            return VulnerabilityIndicator(['error', 'warning', 'exception'], "Generic")
    
    def _cleanup_vulnerability_logs(self):
        """
        Clean up existing vulnerability log files before running POC
        to ensure they don't interfere with fresh detection
        """
        log_files = ['/tmp/sqli.log', '/tmp/cmdi.log']
        
        for log_file in log_files:
            try:
                if os.path.exists(log_file):
                    os.remove(log_file)
                    # print(f"[POC] Removed existing log file: {log_file}")
            except Exception as e:
                print(f"[POC] Warning: Failed to remove {log_file}: {e}")
    
    def make_request(self, url: str, method: str = 'GET', **kwargs) -> requests.Response:
        """Make HTTP request with optional XDEBUG_TRIGGER"""
        if self.use_trigger:
            print(f"[POC] Using request with XDEBUG_TRIGGER")
            return make_request_with_trigger(url, method=method, **kwargs)
        else:
            print(f"[POC] Using standard request")
            return requests.request(method, url, **kwargs)
    
    def check_vulnerability(self, response: requests.Response) -> Tuple[bool, str]:
        """
        Check if response indicates vulnerability
        
        Args:
            response: HTTP response object
            
        Returns:
            tuple: (vulnerability_found: bool, evidence: str)
        """
        found, pattern = self.indicator.check(response.text)
        if found:
            complete_msg = self.indicator.find_complete_message(response.text, pattern)
            print(f"[POC] {self.indicator.name} indicator found: {pattern}")
            # print(f"[POC] Complete message: {complete_msg}")
            return True, complete_msg
        return False, ""
    
    def save_response(self, response: requests.Response, phase: str = None) -> str:
        """
        Save response to file with appropriate naming
        
        Args:
            response: HTTP response object
            phase: Phase identifier (from POC_PHASE env var or custom)
            
        Returns:
            str: Path to saved file
        """
        if phase is None:
            phase = os.environ.get('POC_PHASE', 'unknown')
        
        if phase == 'unknown':
            timestamp = int(time.time())
            file_suffix = f"_{timestamp}"
        else:
            file_suffix = f"_{phase}"
        
        response_file = f'/tmp/{self.app_name.lower()}_{self.cve_id.replace("-", "_")}_response{file_suffix}.html'
        
        if os.path.exists(response_file):
            os.unlink(response_file)
        
        with open(response_file, 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        print(f"[POC] Response saved to {response_file}")
        return response_file
    
    def run_test(self, url: str, method: str = 'GET', **request_kwargs) -> int:
        """
        Run standardized POC test
        
        Args:
            url: Target URL
            method: HTTP method
            **request_kwargs: Additional request parameters
            
        Returns:
            int: Exit code (0=no vuln, 1=vuln detected, 2=request failed)
        """
        print(f"[POC] Testing {self.app_name} {self.cve_id} - {self.vuln_type}")
        print(f"[POC] Target URL: {url}")
        print(f"[POC] Method: {method}")
        
        if 'params' in request_kwargs:
            print(f"[POC] Parameters: {request_kwargs['params']}")
        if 'data' in request_kwargs:
            print(f"[POC] POST Data: {request_kwargs['data']}")
        
        # Clean up existing vulnerability logs before running test
        self._cleanup_vulnerability_logs()
        
        try:
            response = self.make_request(url, method, timeout=10, **request_kwargs)
            print(f"[POC] Status Code: {response.status_code}")
            
            # Save response
            self.save_response(response)
            
            # Check for vulnerability
            vulnerability_found, evidence = self.check_vulnerability(response)
            
            if vulnerability_found:
                print("[POC] Vulnerability detected!")
                save_response_to_crash_file(response)
                save_request_to_crash_file(url, method, 
                                         request_kwargs.get('params'), 
                                         request_kwargs.get('data'))
                return 1  # Exit code 1 for vulnerability detected
            elif len(response.text) == 0:
                print("[POC] Empty response received")
                return 2
            else:
                print("[POC] No obvious vulnerability indicators found")
                return 0  # Exit code 0 for no vulnerability
                
        except Exception as e:
            print(f"[POC] Request failed: {e}")
            return 2  # Exit code 2 for request failure


def create_standard_poc_runner(cve_id: str, app_name: str, vuln_type: str) -> StandardPOCRunner:
    """
    Factory function to create a StandardPOCRunner instance
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2017-8917")
        app_name: Application name (e.g., "Joomla")
        vuln_type: Vulnerability type (e.g., "SQL injection")
        
    Returns:
        StandardPOCRunner: Configured POC runner instance
    """
    return StandardPOCRunner(cve_id, app_name, vuln_type)


def extract_poc_metadata(docstring: str) -> Dict[str, str]:
    """
    Extract metadata from POC docstring
    
    Args:
        docstring: The POC file's docstring
        
    Returns:
        dict: Extracted metadata with keys: app, cve, type, method, description, crash_fields, target_url, params
    """
    metadata = {
        'app': '',
        'cve': '',
        'type': '',
        'method': '',
        'description': '',
        'crash_fields': [],
        'target_url': '',
        'params': ''
    }
    
    lines = docstring.split('\n')
    for line in lines:
        line = line.strip()
        if '[APP]' in line:
            metadata['app'] = line.split('[APP]')[-1].strip()
        elif '[CVE]' in line:
            metadata['cve'] = line.split('[CVE]')[-1].strip()
        elif '[TYPE]' in line:
            metadata['type'] = line.split('[TYPE]')[-1].strip()
        elif '[METHOD]' in line:
            metadata['method'] = line.split('[METHOD]')[-1].strip()
        elif '[CRASH_FIELDS]' in line:
            # Parse crash fields - can be comma-separated list
            crash_fields_str = line.split('[CRASH_FIELDS]')[-1].strip()
            if crash_fields_str:
                # Split by comma and clean up whitespace
                metadata['crash_fields'] = [field.strip() for field in crash_fields_str.split(',') if field.strip()]
        elif '[TARGET_URL]' in line:
            metadata['target_url'] = line.split('[TARGET_URL]')[-1].strip()
        elif '[PARAMS]' in line:
            metadata['params'] = line.split('[PARAMS]')[-1].strip()
        elif line and not line.startswith('[') and not line.startswith('"""'):
            # Collect description lines
            if metadata['description']:
                metadata['description'] += ' '
            metadata['description'] += line
    
    # If no explicit method is found, try to extract from description
    if not metadata['method'] and metadata['description']:
        desc_lower = metadata['description'].lower()
        if 'get method' in desc_lower or 'get /' in desc_lower:
            metadata['method'] = 'GET'
        elif 'post method' in desc_lower or 'post /' in desc_lower:
            metadata['method'] = 'POST'
        elif 'put method' in desc_lower:
            metadata['method'] = 'PUT'
        elif 'delete method' in desc_lower:
            metadata['method'] = 'DELETE'
    
    return metadata


def get_poc_metadata_from_file(file_path: str) -> Dict[str, str]:
    """
    Extract POC metadata from file's docstring
    
    Args:
        file_path: Path to POC file
        
    Returns:
        dict: Extracted metadata with keys: app, cve, type, method, description, crash_fields, target_url, params
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find the first docstring
        lines = content.split('\n')
        in_docstring = False
        docstring_lines = []
        
        for line in lines:
            if '"""' in line and not in_docstring:
                in_docstring = True
                if line.count('"""') == 2:  # Single line docstring
                    docstring_lines.append(line)
                    break
                else:
                    docstring_lines.append(line)
            elif '"""' in line and in_docstring:
                docstring_lines.append(line)
                break
            elif in_docstring:
                docstring_lines.append(line)
        
        docstring = '\n'.join(docstring_lines)
        return extract_poc_metadata(docstring)
    
    except Exception as e:
        print(f"Warning: Could not extract metadata from {file_path}: {e}")
        return {'app': '', 'cve': '', 'type': '', 'method': '', 'description': '', 'crash_fields': [], 'target_url': '', 'params': ''}
def get_unpatched_login_url(base_url: str, login_path: str) -> str:
    """
    Replace the 'from' string in base_url with 'to' string according to configuration to generate target login URL
    
    Args:
        base_url: Original base URL
        login_path: Login path
        
    Returns:
        str: Complete login URL after replacement
    """
    try:
        # Try to read differential testing configuration
        config_files = [
            '/test/witcher_config.json',
            os.path.join(os.path.dirname(__file__), '../witcher_config.json')
        ]
        
        url_pattern = None
        for config_file in config_files:
            if os.path.exists(config_file):
                try:
                    import json
                    with open(config_file, 'r') as f:
                        config = json.load(f)
                        differential_config = config.get("differential_testing", {})
                        if differential_config.get("enabled", False):
                            url_pattern = differential_config.get("url_pattern", {})
                            # print(f"[POC] Found differential testing config in {config_file}")
                            print(f"[POC] URL pattern: {url_pattern}")
                            break
                except Exception as e:
                    print(f"[POC] Error reading config file {config_file}: {e}")
                    continue
        
        # If no configuration found, use environment variables or default values
        if not url_pattern:
            from_pattern = os.environ.get('URL_FROM_PATTERN', '')
            to_pattern = os.environ.get('URL_TO_PATTERN', '')
            if from_pattern and to_pattern:
                url_pattern = {'from': from_pattern, 'to': to_pattern}
                print(f"[POC] Using environment variables for URL pattern: {url_pattern}")
            else:
                print(f"[POC] No URL pattern configuration found, using original URL")
                return base_url.rstrip('/') + '/' + login_path.lstrip('/')
        
        # Execute URL replacement
        from_pattern = url_pattern.get('from', '')
        to_pattern = url_pattern.get('to', '')
        
        if from_pattern and to_pattern and from_pattern in base_url:
            unpatched_base_url = base_url.replace(from_pattern, to_pattern)
            print(f"[POC] URL pattern replacement: '{from_pattern}' -> '{to_pattern}'")
            # print(f"[POC] Original base URL: {base_url}")
            # print(f"[POC] Target base URL: {unpatched_base_url}")
        else:
            unpatched_base_url = base_url
            print(f"[POC] No URL replacement performed (pattern not found or not configured)")
        
        unpatched_login_url = unpatched_base_url.rstrip('/') + '/' + login_path.lstrip('/')
        return unpatched_login_url
        
    except Exception as e:
        print(f"[POC] Error in URL pattern replacement: {e}")
        return base_url.rstrip('/') + '/' + login_path.lstrip('/')


def run_authenticated_poc(base_url: str, login_path: str, login_payload: Dict[str, str], 
                         poc_url: str, poc_payload: Dict[str, str], method: str = 'POST',
                         cve_id: str = '', app_name: str = '', vuln_type: str = '') -> int:
    """
    Generic POC testing function that requires login authentication
    
    Args:
        base_url: Application base URL (e.g., "http://localhost/joomla")
        login_path: Login page path (e.g., "/administrator/index.php")
        login_payload: Login POST data dictionary
        poc_url: POC test URL
        poc_payload: POC test payload data
        method: POC request method ('GET' or 'POST')
        cve_id: CVE number
        app_name: Application name
        vuln_type: Vulnerability type
        
    Returns:
        int: Exit code (0=no vulnerability, 1=vulnerability found, 2=request failed)
    """
    print(f"[POC] Running authenticated POC test")
    print(f"[POC] Base URL: {base_url}")
    print(f"[POC] Login Path: {login_path}")
    print(f"[POC] POC URL: {poc_url}")
    
    # Create POC runner
    poc_runner = StandardPOCRunner(cve_id, app_name, vuln_type) if cve_id else None
    
    # Set common headers
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    try:
        # Step 1: Login to URL2 (unpatched URL after replacement) and save cookies
        unpatched_login_url = get_unpatched_login_url(base_url, login_path)
        if unpatched_login_url != base_url.rstrip('/') + '/' + login_path.lstrip('/'):
            # print(f"[POC] Step 1: Login to URL2 (unpatched URL) to obtain cookies")
            # print(f"[POC] Target login URL: {unpatched_login_url}")
            
            unpatched_session = requests.Session()
            
            # First, visit the login page to initialize session and get session cookie
            initial_response = unpatched_session.get(unpatched_login_url, headers=headers, timeout=10)
            print(f"[POC] Initial visit to URL2 login page status: {initial_response.status_code}")
            
            # Now submit the login form with the session established
            login_response = unpatched_session.post(unpatched_login_url, data=login_payload, headers=headers, 
                                        timeout=10, allow_redirects=True)
            # print(f"[POC] URL2 login response status: {login_response.status_code}")
            
            # Handle redirects
            unpatched_base_url = unpatched_login_url.rsplit('/', 1)[0] if '/' in unpatched_login_url else unpatched_login_url
            current_response = login_response
            redirect_count = 0
            max_redirects = 5
            
            while (300 <= current_response.status_code < 400 and 
                   'location' in current_response.headers and 
                   redirect_count < max_redirects):
                
                location = current_response.headers['location']
                # print(f"[POC] URL2 redirect #{redirect_count + 1} to: {location}")
                
                if location.startswith('/'):
                    from urllib.parse import urlparse
                    parsed_target = urlparse(unpatched_base_url)
                    redirect_url = f"{parsed_target.scheme}://{parsed_target.netloc}{location}"
                elif not location.startswith('http'):
                    redirect_url = unpatched_base_url.rstrip('/') + '/' + location.lstrip('/')
                else:
                    redirect_url = location
                
                current_response = unpatched_session.get(redirect_url, headers=headers, 
                                             timeout=10, allow_redirects=True)
                # print(f"[POC] URL2 redirect response status: {current_response.status_code}")
                redirect_count += 1
            
            # Save URL2 cookies
            unpatched_cookies = dict(unpatched_session.cookies)
            print(f"[POC] URL2 cookies obtained: {unpatched_cookies}")
            
            try:
                import json
                url2_cookies_file = '/tmp/cookies_url2.dat'
                with open(url2_cookies_file, 'w') as f:
                    json.dump(unpatched_cookies, f)
                print(f"[POC] URL2 authenticated session cookies saved to {url2_cookies_file}")
                # print(f"[POC] URL2 cookies were obtained from: {unpatched_login_url}")
            except Exception as e:
                print(f"[POC] Warning: Failed to save URL2 cookies to file: {e}")
        else:
            print(f"[POC] No URL pattern replacement configured, skipping URL2 login")
        
        # Step 2: Login to URL1 (original URL) and execute POC test
        # print(f"[POC] Step 2: Login to URL1 (original URL) and execute POC")
        original_login_url = base_url.rstrip('/') + '/' + login_path.lstrip('/')
        # print(f"[POC] Original login URL: {original_login_url}")
        
        session = requests.Session()
        
        # First, visit the login page to initialize session and get session cookie
        initial_response = session.get(original_login_url, headers=headers, timeout=10)
        print(f"[POC] Initial visit to login page status: {initial_response.status_code}")
        
        # Now submit the login form with the session established
        login_response = session.post(original_login_url, data=login_payload, headers=headers, 
                                    timeout=10, allow_redirects=True)
        # print(f"[POC] URL1 login response status: {login_response.status_code}")
        
        # Handle redirects
        current_response = login_response
        redirect_count = 0
        max_redirects = 5
        
        while (300 <= current_response.status_code < 400 and 
               'location' in current_response.headers and 
               redirect_count < max_redirects):
            
            location = current_response.headers['location']
            # print(f"[POC] URL1 redirect #{redirect_count + 1} to: {location}")
            
            if location.startswith('/'):
                from urllib.parse import urlparse
                parsed_base = urlparse(base_url)
                redirect_url = f"{parsed_base.scheme}://{parsed_base.netloc}{location}"
            elif not location.startswith('http'):
                redirect_url = base_url.rstrip('/') + '/' + location.lstrip('/')
            else:
                redirect_url = location
            
            current_response = session.get(redirect_url, headers=headers, 
                                         timeout=10, allow_redirects=True)
            # print(f"[POC] URL1 redirect response status: {current_response.status_code}")
            redirect_count += 1
        
        if redirect_count >= max_redirects:
            print(f"[POC] Warning: Maximum redirects ({max_redirects}) reached")
        
        # Display and save URL1 cookies
        patched_cookies = dict(session.cookies)
        print(f"[POC] URL1 cookies obtained: {patched_cookies}")
        
        try:
            import json
            url1_cookies_file = '/tmp/cookies_url1.dat'
            with open(url1_cookies_file, 'w') as f:
                json.dump(patched_cookies, f)
            print(f"[POC] URL1 authenticated session cookies saved to {url1_cookies_file}")
            print(f"[POC] URL1 cookies were obtained from: {original_login_url}")
        except Exception as e:
            print(f"[POC] Warning: Failed to save URL1 cookies to file: {e}")
        
        # For compatibility, also save to the original filename (using URL1 cookies)
        try:
            import json
            cookies_file = '/tmp/cookies.dat'
            with open(cookies_file, 'w') as f:
                json.dump(patched_cookies, f)
            # print(f"[POC] URL1 cookies also saved to {cookies_file} for compatibility")
        except Exception as e:
            print(f"[POC] Warning: Failed to save cookies to compatibility file: {e}")
        
        # Step 3: Execute POC test using URL1's authenticated session
        print(f"[POC] Executing POC test with URL1 authenticated session")
        print(f"[POC] Method: {method}")
        print(f"[POC] POC Payload: {poc_payload}")
        
        # Clean up existing vulnerability logs before running test
        if poc_runner:
            poc_runner._cleanup_vulnerability_logs()
        else:
            cleanup_vulnerability_logs()
        
        # Whether to use XDEBUG_TRIGGER
        cleanup_coverage_files()
        use_trigger = os.environ.get('USE_XDEBUG_TRIGGER', 'true').lower() == 'true'
        if use_trigger:
            session.cookies.set('XDEBUG_TRIGGER', '1')
            print(f"[POC] XDEBUG_TRIGGER enabled")

        if method.upper() == 'GET':
            poc_response = session.get(poc_url, params=poc_payload, headers=headers, timeout=10)
        elif method.upper() == 'POST':
            poc_response = session.post(poc_url, data=poc_payload, headers=headers, timeout=10)
        else:
            poc_response = session.request(method, poc_url, data=poc_payload, headers=headers, timeout=10)
        
        print(f"[POC] POC response status: {poc_response.status_code}")
        
        # Step 4: Check vulnerability indicators
        if poc_runner:
            # Save response
            poc_runner.save_response(poc_response)
            
            # Check vulnerability
            vulnerability_found, evidence = poc_runner.check_vulnerability(poc_response)
            
            if vulnerability_found:
                print("[POC] Vulnerability detected!")
                save_response_to_crash_file(poc_response)
                save_request_to_crash_file(poc_url, method, 
                                         poc_payload if method.upper() == 'GET' else None,
                                         poc_payload if method.upper() == 'POST' else None)
                return 1  # Exit code 1 for vulnerability detected
            elif len(poc_response.text) == 0:
                print("[POC] Empty response received")
                return 2
            else:
                print("[POC] No obvious vulnerability indicators found")
                return 0  # Exit code 0 for no vulnerability
        else:
            # If no POC runner available, only save response
            save_response_to_crash_file(poc_response)
            print("[POC] Response saved, no vulnerability checking performed")
            return 0
            
    except Exception as e:
        print(f"[POC] Request failed: {e}")
        return 2  # Exit code 2 for request failure

def safe_remove_files(directory, pattern):
    """
    Safely remove files matching a pattern in a directory.
    Uses find command to handle large number of files without hitting argument limits.
    
    Args:
        directory (str): Directory path to search in
        pattern (str): File pattern to match (e.g., "*.json", "trace*.xt")
    
    Returns:
        bool: True if operation completed successfully, False otherwise
    """
    try:
        import subprocess
        import os
        
        if not os.path.exists(directory):
            return True  # Directory doesn't exist, nothing to remove
            
        result = subprocess.run(
            ["sudo", "find", directory, "-name", pattern, "-type", "f", "-exec", "sudo", "rm", "-f", "{}", ";"],
            check=False, 
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0 and result.stderr:
            print(f"Warning: Error removing files {pattern} from {directory}: {result.stderr.strip()}")
            return False
            
        return True
        
    except Exception as e:
        print(f"Error in safe_remove_files: {e}")
        return False

def cleanup_coverage_files():
    """
    Clean up coverage and trace files safely.
    Handles large number of files without hitting shell argument limits.
    """
    cleanup_operations = [
        ("/dev/shm/traces", "trace*.xt"),
        ("/dev/shm/coverages", "*.json"),
    ]
    
    for directory, pattern in cleanup_operations:
        safe_remove_files(directory, pattern)
    
    print("Coverage cleanup completed")

def cleanup_vulnerability_logs():
    """
    Clean up existing vulnerability log files
    Standalone function that can be used independently of StandardPOCRunner
    """
    log_files = ['/tmp/sqli.log', '/tmp/cmdi.log']
    
    for log_file in log_files:
        try:
            if os.path.exists(log_file):
                os.remove(log_file)
                print(f"[UTILS] Removed existing log file: {log_file}")
        except Exception as e:
            print(f"[UTILS] Warning: Failed to remove {log_file}: {e}")