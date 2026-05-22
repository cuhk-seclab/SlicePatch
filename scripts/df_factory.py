#!/usr/bin/env python3


import os
import pwd
import json
from poces.utils import get_poc_metadata_from_file
import grp
import shutil
import subprocess
from utils import cleanup_coverage_files
import time
import glob
import threading
from poc_factory import *
import signal
from pathlib import Path
from typing import Tuple, Optional, List
from urllib.parse import unquote


class Predator:
    

    def __init__(self, working_directory: str = None, poc_factory_inst: POCFactory = None):
        
        self.working_directory = working_directory or os.getcwd()
        self.poc_factory_inst = poc_factory_inst
        self.monitoring_active = False
        self.differential_monitor_thread = None
        self.crashes_monitor_thread = None
        self.apache_monitor_thread = None
        self.xss_monitor_thread = None
        self.witcher_process = None
        self.differential_found = False
        self.crashes_found = False
        self.apache_error_found = False
        self.xss_found = False
        self.found_files = []
        
    def switch_to_wc_user(self) -> bool:
        
        try:
            # Get wc user information
            wc_user = pwd.getpwnam('wc')
            wc_uid = wc_user.pw_uid
            wc_gid = wc_user.pw_gid
            
            # Switch to wc user
            os.setgid(wc_gid)
            os.setuid(wc_uid)
            
            print(f"Successfully switched to user 'wc' (UID: {wc_uid}, GID: {wc_gid})")
            return True
            
        except KeyError:
            print("Error: User 'wc' not found on the system")
            return False
        except PermissionError:
            print("Error: Insufficient permissions to switch to user 'wc'")
            return False
        except Exception as e:
            print(f"Error switching to user 'wc': {e}")
            return False
    
    def get_witcher_command(self) -> str:
        
        # Calculate affinity based on network interface
        try:
            # Get the 4th octet of the 172.x.x.x IP address
            ifconfig_cmd = "ifconfig | egrep -oh 'inet 172[\.0-9]+' | cut -d '.' -f4"
            result = subprocess.run(ifconfig_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                fourth_octet = int(result.stdout.strip())
                affinity = (fourth_octet * 13) % 192
            else:
                print("Warning: Could not determine network interface, using default affinity 1")
                affinity = 1

        except Exception as e:
            print(f"Warning: Error calculating affinity: {e}, using default affinity 1")
            affinity = 1
        
        return f"python3 -m witcher --affinity {affinity}"
    
    def _robust_rmtree(self, path: str, max_attempts: int = 3) -> bool:
        
        for attempt in range(1, max_attempts + 1):
            try:
                if not os.path.exists(path):
                    return True
                    
                print(f"Attempt {attempt}/{max_attempts}: Removing {path}")
                
                # First try: Standard shutil.rmtree with error handler
                def handle_remove_readonly(func, path, exc):
                    
                    if os.path.exists(path):
                        os.chmod(path, 0o777)
                        func(path)
                
                shutil.rmtree(path, onerror=handle_remove_readonly)
                
                # Verify removal
                if not os.path.exists(path):
                    print(f"Successfully removed {path}")
                    return True
                    
            except Exception as e:
                print(f"Attempt {attempt} failed with shutil.rmtree: {e}")
                
                # Fallback: Try with subprocess rm -rf
                try:
                    print(f"Fallback attempt {attempt}: Using rm -rf")
                    subprocess.run(['rm', '-rf', path], check=True, timeout=30)
                    
                    if not os.path.exists(path):
                        print(f"Successfully removed {path} with rm -rf")
                        return True
                        
                except subprocess.CalledProcessError as rm_error:
                    print(f"rm -rf failed: {rm_error}")
                except subprocess.TimeoutExpired:
                    print(f"rm -rf timed out")
                except Exception as rm_error:
                    print(f"rm -rf error: {rm_error}")
            
            # Wait before next attempt
            if attempt < max_attempts:
                print(f"Waiting before next attempt...")
                time.sleep(2)
        
        # Final check and warning
        if os.path.exists(path):
            print(f"WARNING: Could not completely remove {path} after {max_attempts} attempts")
            # List what's left for debugging
            try:
                remaining = subprocess.run(['find', path, '-type', 'f'], 
                                        capture_output=True, text=True, timeout=10)
                if remaining.stdout:
                    print(f"Remaining files:\n{remaining.stdout}")
            except:
                pass
            return False
        
        return True
    
    def monitor_differential(self) -> None:
        
        print("Starting differential monitoring...")
        
        while self.monitoring_active:
            try:
                # Check for differential test files
                differential_dir = os.path.join(self.working_directory, "WICHR", "work", "differential")
                if os.path.exists(differential_dir):
                    cmp_files = glob.glob(os.path.join(differential_dir, "*.cmp"))
                    
                    for cmp_file in cmp_files:
                        if os.path.getsize(cmp_file) > 0:  # Non-empty file
                            print(f"DIFFERENTIAL FOUND: Non-empty .cmp file detected: {cmp_file}")
                            self.differential_found = True
                            self.found_files.append(cmp_file)
                            self.monitoring_active = False
                            return
                
                # Sleep for a short interval before checking again
                time.sleep(1)
                
            except Exception as e:
                print(f"Error during differential monitoring: {e}")
                time.sleep(1)
        
        print("Differential monitoring stopped")
    
    def monitor_crashes(self) -> None:
        
        print("Starting crash monitoring...")
        
        while self.monitoring_active:
            try:
                # Check for crash files
                crashes_pattern = os.path.join(self.working_directory, "WICHR", "work", "*", "crashes", "id*")
                crash_files = glob.glob(crashes_pattern)
                
                for crash_file in crash_files:
                    if os.path.getsize(crash_file) > 0:  # Non-empty file

                        # Check if crash_fields are included, if not, skip it
                        try:
                            if os.path.exists('witcher_config.json'):
                                with open('witcher_config.json', 'r') as f:
                                    witcher_config = json.load(f)
                                poc_path = witcher_config.get('differential_testing', {}).get('poc_path', '')
                            else:
                                # Fallback: try to get POC path from poc_factory_inst
                                poc_path = getattr(self.poc_factory_inst, 'poc_file_path', '') if self.poc_factory_inst else ''
                            
                            if poc_path and os.path.exists(poc_path):
                                metadata = get_poc_metadata_from_file(poc_path)
                                crash_fields = metadata.get('crash_fields', [])
                                
                                if crash_fields:
                                    crash_fields_all_included = True
                                    with open(crash_file, 'rb') as f:
                                        crash_string = f.read().decode('utf-8', errors='replace')
                                    for field in crash_fields:
                                        field_decoded = unquote(field)
                                        crash_string_decoded = unquote(crash_string)
                                        if (field_decoded + '=') not in crash_string_decoded:
                                            crash_fields_all_included = False
                                            break
                                    
                                    if not crash_fields_all_included:
                                        print(f"CRASH SKIPPED: Crash file {crash_file}, {crash_fields}, not a true crash")
                                        os.unlink(crash_file)  # Remove it to avoid clutter
                                        continue

                        except Exception as config_error:
                            print(f"Warning: Could not check crash_fields for {crash_file}: {config_error}")
                        

                        # If we reach here, it's a real crash
                        print(f"CRASH FOUND: Non-empty crash file detected: {crash_file}")
                        self.crashes_found = True
                        self.found_files.append(crash_file)
                        self.monitoring_active = False
                        return
                
                # Sleep for a short interval before checking again
                time.sleep(1)
                
            except Exception as e:
                print(f"Error during crash monitoring: {e}")
                time.sleep(1)
        
        print("Crash monitoring stopped")
    
    def monitor_xss(self) -> None:
        
        print("Starting XSS monitoring...")
        
        while self.monitoring_active:
            try:
                # Check for XSS test files in WICHR/work directory
                xss_pattern = os.path.join(self.working_directory, "WICHR", "work", "*.xss")
                xss_files = glob.glob(xss_pattern)
                
                # Also check subdirectories
                xss_subdir_pattern = os.path.join(self.working_directory, "WICHR", "work", "*", "*.xss")
                xss_subdir_files = glob.glob(xss_subdir_pattern)
                
                all_xss_files = xss_files + xss_subdir_files
                
                for xss_file in all_xss_files:
                    if os.path.getsize(xss_file) > 0:  # Non-empty file
                        print(f"XSS FOUND: Non-empty .xss file detected: {xss_file}")
                        self.xss_found = True
                        self.found_files.append(xss_file)
                        self.monitoring_active = False
                        return
                
                # Sleep for a short interval before checking again
                time.sleep(1)
                
            except Exception as e:
                print(f"Error during XSS monitoring: {e}")
                time.sleep(1)
        
        print("XSS monitoring stopped")
    
    def execute_witcher_with_monitoring(self, timeout: int = 60) -> Tuple[bool, str, List[str]]:
        
        try:
            # Switch to wc user
            if not self.switch_to_wc_user():
                return False, "Failed to switch to 'wc' user", []
            
            # Change to working directory
            os.chdir(self.working_directory)
            print(f"Changed to working directory: {self.working_directory}")
            
            # Remove WICHR directory with robust cleanup
            wichr_path = os.path.join(self.working_directory, 'WICHR')
            if os.path.exists(wichr_path):
                print(f"Cleaning up existing WICHR directory: {wichr_path}")
                self._robust_rmtree(wichr_path)
                time.sleep(2)  # Brief pause after cleanup
            
            # Get Witcher command
            witcher_cmd = self.get_witcher_command()
            print(f"Executing command: {witcher_cmd}")
            
            # Reset monitoring state
            self.monitoring_active = True
            self.differential_found = False
            self.crashes_found = False
            self.apache_error_found = False
            self.xss_found = False
            self.found_files = []
            if os.path.exists('/tmp/start_test.dat'):
                os.system('sudo rm -f /tmp/start_test.dat')
            cleanup_coverage_files()
            
            # Start separate monitoring threads
            self.differential_monitor_thread = threading.Thread(target=self.monitor_differential)
            self.differential_monitor_thread.daemon = True
            self.differential_monitor_thread.start()
            
            self.crashes_monitor_thread = threading.Thread(target=self.monitor_crashes)
            self.crashes_monitor_thread.daemon = True
            self.crashes_monitor_thread.start()
            
            # Start XSS monitoring thread
            self.xss_monitor_thread = threading.Thread(target=self.monitor_xss)
            self.xss_monitor_thread.daemon = True
            self.xss_monitor_thread.start()
            
            # Start Apache error monitoring thread
            self.apache_monitor_thread = threading.Thread(target=self.monitor_apache_errors)
            self.apache_monitor_thread.daemon = True
            self.apache_monitor_thread.start()

            # Execute Witcher command with real-time output to screen
            print(f"Starting Witcher process with real-time output...")
            self.witcher_process = subprocess.Popen(
                witcher_cmd,
                shell=True,
                stdout=None,  # Output directly to terminal
                stderr=None,  # Error output directly to terminal  
                text=True,
                preexec_fn=os.setsid  # Create new process group for clean termination
            )
            
            # Wait for process completion or timeout
            start_time = time.time()
            while self.witcher_process.poll() is None and self.monitoring_active:
                if time.time() - start_time > timeout:
                    print(f"Timeout reached ({timeout}s), terminating Witcher process...")
                    self.terminate_witcher_process()
                    self.monitoring_active = False
                    return True, f"Timeout reached after {timeout} seconds, no differential/crashes found", []
                
                time.sleep(1)
            
            # Stop monitoring
            self.monitoring_active = False
            
            # Check results
            if self.differential_found:
                reason = "Differential test failure detected."
                # Find the first non-empty .cmp in WICHR/work/differential
                cmp_files = glob.glob(os.path.join(self.working_directory, "WICHR", "work", "differential", "*.cmp"))
                if cmp_files:
                    cmp_file = cmp_files[0]
                    with open(cmp_file, 'r') as f:
                        reason += f"\nDetails:\n"
                        # skip all lines until the first "=== REQUEST INPUT ===", add it and following lines
                        lines = f.readlines()
                        skip = True
                        for line in lines:
                            if "=== REQUEST INPUT ===" in line:
                                skip = False
                            if not skip:
                                reason += line.strip() + "\n"
                return False, reason, self.found_files
            
            elif self.apache_error_found:
                reason = "PHP error detected in Apache log. Please check the syntax of the patch."
                # Read the actual error content from Apache log
                try:
                    apache_log_path = "/var/log/apache2/error.log"
                    tail_cmd = f"sudo tail -n 10 {apache_log_path}"
                    result = subprocess.run(
                        tail_cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0 and result.stdout:
                        recent_logs = result.stdout.strip()
                        # Filter for PHP errors
                        php_errors = [line for line in recent_logs.split('\n') if '[php7:error]' in line]
                        if php_errors:
                            reason += f"\nLast PHP error:\n" + php_errors[-1]  # Last PHP error
                except Exception as e:
                    reason += f"\n(Could not read Apache log details: {e})"
                return False, reason, self.found_files
            
            elif self.xss_found:
                reason = "XSS test failure detected."
                # Find the first non-empty .xss file in WICHR/work
                xss_files = glob.glob(os.path.join(self.working_directory, "WICHR", "work", "*.xss"))
                xss_subdir_files = glob.glob(os.path.join(self.working_directory, "WICHR", "work", "*", "*.xss"))
                all_xss_files = xss_files + xss_subdir_files
                
                if all_xss_files:
                    xss_file = all_xss_files[0]
                    try:
                        with open(xss_file, 'r', encoding='utf-8', errors='replace') as f:
                            xss_content = f.read().strip().splitlines()[:10]  # Read first 10 lines
                            xss_content = "\n".join(xss_content)
                            reason += f"\nXSS test details:\n{xss_content}"
                    except Exception as e:
                        reason += f"\n(Could not read XSS file details: {e})"
                return False, reason, self.found_files
            
            elif self.crashes_found:
                # return False, "Crash files detected", self.found_files
                reason = "The vulnerability was not fixed."
                # Find the first non-empty crash file in WICHR/work/*/crashes
                crash_files = glob.glob(os.path.join(self.working_directory, "WICHR", "work", "*", "crashes", "id*"))
                if crash_files:
                    crash_file = crash_files[0]
                    
                    with open(crash_file, 'rb') as f:
                        crash_content = f.read().decode('utf-8', errors='replace')
                        reason += f"\nThis request can still trigger the vulnerability: {crash_content}"
                    
                    # Send the crash content as a request and show the cleaned response
                    try:
                        cleaned_response = self._send_crash_request_and_get_response(crash_content)
                        if cleaned_response:
                            reason += f"\n\nServer response:\n{cleaned_response}"
                    except Exception as e:
                        reason += f"\n\nError sending crash request: {e}"

                return False, reason, self.found_files
            
            else:
                # Process completed normally without differential/crashes
                return_code = self.witcher_process.returncode
                return False, f"Witcher stopped with return code {return_code}", []

        except Exception as e:
            self.monitoring_active = False
            return False, f"Error executing Witcher: {e}", []
        
        finally:
            # Cleanup
            self.cleanup()
    
    def terminate_witcher_process(self) -> None:
        
        if self.witcher_process and self.witcher_process.poll() is None:
            try:
                # Terminate the entire process group
                os.killpg(os.getpgid(self.witcher_process.pid), signal.SIGTERM)
                
                # Wait for termination
                time.sleep(2)
                
                # Force kill if still running
                if self.witcher_process.poll() is None:
                    os.killpg(os.getpgid(self.witcher_process.pid), signal.SIGKILL)
                    
                print("Witcher process terminated")
                
            except Exception as e:
                print(f"Error terminating Witcher process: {e}")
    
    def cleanup(self) -> None:
        
        self.monitoring_active = False
        
        if self.differential_monitor_thread and self.differential_monitor_thread.is_alive():
            self.differential_monitor_thread.join(timeout=5)
        
        if self.crashes_monitor_thread and self.crashes_monitor_thread.is_alive():
            self.crashes_monitor_thread.join(timeout=5)
        
        if self.xss_monitor_thread and self.xss_monitor_thread.is_alive():
            self.xss_monitor_thread.join(timeout=5)
        
        if self.apache_monitor_thread and self.apache_monitor_thread.is_alive():
            self.apache_monitor_thread.join(timeout=5)
        
        if self.witcher_process and self.witcher_process.poll() is None:
            self.terminate_witcher_process()
    
    def verify_differential_fuzzing(self, timeout: int = 3600) -> Tuple[bool, str, List[str]]:
        
        
        try:
            success, reason, found_files = self.execute_witcher_with_monitoring(timeout)
            
            # print(f"\n{'='*60}")
            # print("DIFFERENTIAL FUZZING RESULTS")
            # print(f"{'='*60}")
            # print(f"Result: {'PASSED' if success else 'FAILED'}")
            # print(f"Reason: {reason}")
            
            # if found_files:
            #     print("Found files:")
            #     for file_path in found_files:
            #         print(f"  - {file_path}")
            
            return success, reason, found_files
            
        except Exception as e:
            error_msg = f"Unexpected error during differential fuzzing verification: {e}"
            print(f"ERROR: {error_msg}")
            return False, error_msg, []
        
        finally:
            self.cleanup()

    def _should_stop_for_apache_error(self, error_line: str) -> bool:
        
        try:
            # Read the backup file list
            patch_bak_path = "/tmp/patch_bak.log"
            if not os.path.exists(patch_bak_path):
                print(f"Warning: {patch_bak_path} not found, will monitor all PHP errors")
                return True  # If no backup list, treat all errors as relevant
            
            monitored_files = set()
            with open(patch_bak_path, 'r') as f:
                for line in f:
                    bak_file = line.strip()
                    if bak_file.endswith('.bak'):
                        # Remove .bak suffix to get the original file path
                        original_file = bak_file[:-4]  # Remove last 4 characters (.bak)
                        monitored_files.add(original_file)
            
            if not monitored_files:
                print("Warning: No monitored files found in patch_bak.log")
                return True
            
            # print(f"Debug: Monitoring {len(monitored_files)} files for Apache errors")
            
            # Check if the error line contains any of our monitored files
            for monitored_file in monitored_files:
                if monitored_file in error_line:
                    # print(f"Debug: Error involves monitored file: {monitored_file}")
                    return True
            
            # print("Debug: Error does not involve any monitored files")
            return False
            
        except Exception as e:
            print(f"Error reading patch backup list: {e}")
            return True  # If we can't read the list, treat all errors as relevant

    def monitor_apache_errors(self) -> None:
        
        print("Starting Apache error log monitoring...")
        apache_log_path = "/var/log/apache2/error.log"
        os.system("sudo truncate -s 0 " + apache_log_path)  # Clear log for fresh monitoring
        
        while self.monitoring_active:
            try:
                # Execute tail command as root to read new lines
                tail_cmd = f"sudo tail -n 1 {apache_log_path}"
                result = subprocess.run(
                    tail_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0 and result.stdout:
                    new_lines = result.stdout.strip()
                    benign_patterns = ['hacking attempt', 'unable to create']
                    if "[php7:error]" in new_lines:
                        no_benign_errors = True
                        for pattern in benign_patterns:
                            if pattern in new_lines.lower():
                                no_benign_errors = False
                                # print(f"Benign error detected: {new_lines}")
                                break
                        # Check if the error is related to files we're monitoring
                        if self._should_stop_for_apache_error(new_lines) and no_benign_errors:
                            print(f"APACHE ERROR FOUND: PHP7 error detected in monitored file")
                            print(f"Error content: {new_lines}")
                            self.apache_error_found = True
                            self.found_files.append(apache_log_path)
                            self.monitoring_active = False
                            return
                        else:
                            # print(f"Apache error detected in non-monitored file, clearing log and continuing...")
                            # print(f"Error content: {new_lines}")
                            # Clear the Apache log to avoid repeated detection
                            os.system("sudo truncate -s 0 " + apache_log_path)
                
                # Sleep for a short interval before checking again
                time.sleep(1)
                
            except subprocess.TimeoutExpired:
                print("Warning: Apache log read timeout")
                time.sleep(1)
            except Exception as e:
                time.sleep(1)
        
        print("Apache monitoring stopped")

    def _send_crash_request_and_get_response(self, crash_content: str) -> str:
        
        try:
            # Read cookies from /tmp/cookies_url1.dat
            cookies = {}
            cookies_file = '/tmp/cookies_url1.dat'
            if os.path.exists(cookies_file):
                try:
                    with open(cookies_file, 'r') as f:
                        cookies = json.load(f)
                    print(f"[CRASH_REQUEST] Loaded cookies from {cookies_file}")
                except Exception as e:
                    print(f"[CRASH_REQUEST] Warning: Failed to load cookies: {e}")
            else:
                print(f"[CRASH_REQUEST] Warning: Cookies file {cookies_file} not found")
            
            # Get POC URL from witcher_config.json
            poc_url = None
            try:
                if os.path.exists('witcher_config.json'):
                    with open('witcher_config.json', 'r') as f:
                        witcher_config = json.load(f)
                    poc_path = witcher_config.get('differential_testing', {}).get('poc_path', '')
                    
                    if poc_path and os.path.exists(poc_path):
                        # Get metadata from POC file
                        from poces.utils import get_poc_metadata_from_file
                        metadata = get_poc_metadata_from_file(poc_path)
                        poc_url = metadata.get('target_url', '')
                        print(f"[CRASH_REQUEST] POC URL from metadata: {poc_url}")
                    
                    if not poc_url:
                        # Fallback: try to get from poc_factory_inst
                        if hasattr(self, 'poc_factory_inst') and self.poc_factory_inst:
                            if hasattr(self.poc_factory_inst, 'target_url'):
                                poc_url = self.poc_factory_inst.target_url
                                print(f"[CRASH_REQUEST] POC URL from poc_factory: {poc_url}")
                
            except Exception as e:
                print(f"[CRASH_REQUEST] Error getting POC URL: {e}")
            
            if not poc_url:
                return "Error: Could not determine POC URL"
            
            # Parse crash content as URL parameters
            from urllib.parse import parse_qs, unquote, urlparse
            
            # Clean up crash content - remove any binary characters
            crash_content_clean = ''.join(char for char in crash_content if ord(char) < 128)
            
            # Try to parse as query parameters
            try:
                # If it looks like a URL, extract the query part
                if 'http' in crash_content_clean and '?' in crash_content_clean:
                    parsed_url = urlparse(crash_content_clean)
                    query_string = parsed_url.query
                else:
                    # Treat the whole content as query string
                    query_string = crash_content_clean.strip()
                
                # Parse parameters
                params = {}
                if query_string:
                    parsed_params = parse_qs(query_string, keep_blank_values=True)
                    # Convert lists to single values
                    for key, value_list in parsed_params.items():
                        if value_list:
                            params[key] = value_list[0] if len(value_list) == 1 else value_list
                        else:
                            params[key] = ''
                
                print(f"[CRASH_REQUEST] Parsed parameters: {params}")
                
            except Exception as e:
                print(f"[CRASH_REQUEST] Error parsing crash content: {e}")
                return f"Error parsing crash content: {e}"
            
            # Prepare headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
            
            # Add XDEBUG_TRIGGER to cookies for debugging
            if cookies:
                cookies['XDEBUG_TRIGGER'] = '1'
            else:
                cookies = {'XDEBUG_TRIGGER': '1'}
            
            # Send request (try both GET and POST methods)
            import requests
            response = None
            
            # Try GET request first
            try:
                print(f"[CRASH_REQUEST] Sending GET request to {poc_url}")
                response = requests.get(
                    poc_url,
                    params=params,
                    cookies=cookies,
                    headers=headers,
                    timeout=15,
                    allow_redirects=True
                )
                print(f"[CRASH_REQUEST] GET response status: {response.status_code}")
                
            except Exception as get_error:
                print(f"[CRASH_REQUEST] GET request failed: {get_error}")
                
                # Try POST request as fallback
                try:
                    print(f"[CRASH_REQUEST] Trying POST request to {poc_url}")
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    response = requests.post(
                        poc_url,
                        data=params,
                        cookies=cookies,
                        headers=headers,
                        timeout=15,
                        allow_redirects=True
                    )
                    print(f"[CRASH_REQUEST] POST response status: {response.status_code}")
                    
                except Exception as post_error:
                    print(f"[CRASH_REQUEST] POST request also failed: {post_error}")
                    return f"Request failed - GET: {get_error}, POST: {post_error}"
            
            if response is None:
                return "Error: No valid response received"
            
            # Clean and return response
            cleaned_response = self._clean_dynamic_content(response.content)
            
            return cleaned_response
            
        except Exception as e:
            print(f"[CRASH_REQUEST] Unexpected error: {e}")
            return f"Unexpected error: {e}"

    def _clean_dynamic_content(self, response_content):
        
        try:
            # Convert to string if it's bytes, with robust encoding handling
            if isinstance(response_content, bytes):
                # Try multiple encoding strategies
                content_str = None
                for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']:
                    try:
                        content_str = response_content.decode(encoding, errors='ignore')
                        break
                    except (UnicodeDecodeError, LookupError):
                        continue
                
                if content_str is None:
                    # Final fallback: use utf-8 with replace errors
                    content_str = response_content.decode('utf-8', errors='replace')
            else:
                content_str = str(response_content)
            
            # Split headers and body
            if '\r\n\r\n' in content_str:
                headers, body = content_str.split('\r\n\r\n', 1)
            elif '\n\n' in content_str:
                headers, body = content_str.split('\n\n', 1)
            else:
                headers, body = '', content_str
            
            # Clean headers - remove dynamic headers
            cleaned_headers = []
            dynamic_headers = [
                'set-cookie', 'date', 'expires', 'last-modified', 'etag',
                'x-request-id', 'x-trace-id', 'x-correlation-id',
                'server', 'x-powered-by', 'x-runtime', 'x-frame-options'
            ]
            
            for line in headers.split('\n'):
                line = line.strip()
                if ':' in line:
                    header_name = line.split(':', 1)[0].strip().lower()
                    if header_name not in dynamic_headers:
                        cleaned_headers.append(line)
                else:
                    cleaned_headers.append(line)
            
            # Try to parse body as HTML for more sophisticated cleaning
            try:
                try:
                    from bs4 import BeautifulSoup, Comment
                    soup = BeautifulSoup(body, 'html.parser')
                except ImportError:
                    raise ImportError("BeautifulSoup not available")
                
                # Remove JavaScript and CSS
                for script in soup(['script', 'style']):
                    script.decompose()
                
                # Remove comments
                for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
                    comment.extract()
                
                # Remove common dynamic attributes
                dynamic_attrs = ['id', 'data-timestamp', 'data-session', 'nonce']
                for tag in soup.find_all():
                    for attr in dynamic_attrs:
                        if tag.has_attr(attr):
                            del tag[attr]
                
                # Remove form tokens and CSRF tokens
                for input_tag in soup.find_all('input'):
                    if input_tag.get('name') in ['_token', 'csrf_token', 'authenticity_token']:
                        input_tag.decompose()
                
                # Get cleaned text
                cleaned_body = soup.get_text(separator=' ', strip=True)
                
            except ImportError:
                self.log_event("BeautifulSoup not available, using basic text cleaning")
                # Basic cleaning without BeautifulSoup
                import re
                
                # Remove JavaScript blocks
                cleaned_body = re.sub(r'<script[^>]*>.*?</script>', '', body, flags=re.DOTALL | re.IGNORECASE)
                
                # Remove CSS blocks
                cleaned_body = re.sub(r'<style[^>]*>.*?</style>', '', cleaned_body, flags=re.DOTALL | re.IGNORECASE)
                
                # Remove HTML comments
                cleaned_body = re.sub(r'<!--.*?-->', '', cleaned_body, flags=re.DOTALL)
                
                # Remove HTML tags and get text content
                cleaned_body = re.sub(r'<[^>]+>', ' ', cleaned_body)
                
                # Remove multiple whitespaces
                cleaned_body = re.sub(r'\s+', ' ', cleaned_body).strip()
            
            except Exception as e:
                self.log_event(f"Error parsing HTML content: {e}, using raw text")
                # Fallback to raw text
                cleaned_body = body
            
            # Combine cleaned headers and body
            cleaned_content = '\n'.join(cleaned_headers) + '\n\n' + cleaned_body
            
            # Additional text normalization
            import re
            # Remove timestamps (various formats)
            cleaned_content = re.sub(r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}', '[TIMESTAMP]', cleaned_content)
            cleaned_content = re.sub(r'\d{10,13}', '[TIMESTAMP]', cleaned_content)  # Unix timestamps
            
            # Remove session IDs and tokens
            cleaned_content = re.sub(r'[a-f0-9]{32,}', '[TOKEN]', cleaned_content, flags=re.IGNORECASE)
            
            # Remove UUIDs
            cleaned_content = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '[UUID]', cleaned_content, flags=re.IGNORECASE)
            
            # Normalize whitespace
            cleaned_content = re.sub(r'\s+', ' ', cleaned_content).strip()
            
            return cleaned_content
            
        except Exception as e:
            self.log_event(f"Error cleaning dynamic content: {e}")
            # Return original content if cleaning fails, with robust encoding handling
            if isinstance(response_content, bytes):
                # Try multiple encoding strategies for fallback
                for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']:
                    try:
                        return response_content.decode(encoding, errors='ignore')
                    except (UnicodeDecodeError, LookupError):
                        continue
                # Final fallback
                return response_content.decode('utf-8', errors='replace')
            return str(response_content)
    
def create_predator(working_directory: str = None, poc_factory_inst: POCFactory = None) -> Predator:
    
    return Predator(working_directory, poc_factory_inst)