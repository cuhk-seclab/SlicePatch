import os
import re
import math
import shutil
import time
import threading
import subprocess
import json
from time import sleep
from math import nan
import argparse

class BudgetExceededException(Exception):
    
    pass

class GlobalBudgetManager:
    
    
    _instance = None
    _initialized = False
    
    def __new__(cls, max_total_tokens=None, max_total_cost=None):
        if cls._instance is None:
            cls._instance = super(GlobalBudgetManager, cls).__new__(cls)
        return cls._instance
    
    def __init__(self, max_total_tokens=None, max_total_cost=None):
        if self._initialized:
            return
        
        # Token and cost tracking
        self.total_tokens_used = 0
        self.total_cost = 0.0
        self.token_usage_log = []
        
        # Budget limits (optional)
        self.max_total_tokens = max_total_tokens
        self.max_total_cost = max_total_cost
        
        # Model pricing (per 1K tokens)
        self.model_pricing = {
            'deepseek-chat': {'input': 0.0002, 'output': 0.0011},  # DeepSeek pricing
            'deepseek-reasoner': {'input': 0.0004, 'output': 0.0022},  # DeepSeek Thinking pricing

            'claude-3-7-sonnet-20250219-all': {'input': 0.003, 'output': 0.015},
            'claude-3-7-sonnet-20250219-low': {'input': 0.003, 'output': 0.015},
            'claude-3-7-sonnet-20250219': {'input': 0.003, 'output': 0.015},

            'claude-sonnet-4-20250514': {'input': 0.003, 'output': 0.015},

            'gpt-4o': {'input': 0.005, 'output': 0.02},

            'gpt-5': {'input': 0.00125, 'output': 0.01},

            'gemini-2.5-flash-nothinking': {'input': 0.0003, 'output': 0.0025},
            'gemini-2.5-pro': {'input': 0.00125, 'output': 0.01},
        }
        
        self._initialized = True
    
    @classmethod
    def reset(cls):
        
        cls._instance = None
        cls._initialized = False
    
    def set_budget(self, max_total_tokens, max_total_cost):
        
        self.max_total_tokens = max_total_tokens
        self.max_total_cost = max_total_cost
        print(f"Budget set: {max_total_tokens} tokens, ${max_total_cost}")

class TokenTracker:
    
    
    def __init__(self, max_total_tokens=None, max_total_cost=None, use_global_budget=True):
        # Use global budget manager if enabled, otherwise create local tracking
        if use_global_budget:
            self.budget_manager = GlobalBudgetManager()
            # If budget parameters are provided, set them in the global manager
            if max_total_tokens is not None or max_total_cost is not None:
                if max_total_tokens: self.budget_manager.max_total_tokens = max_total_tokens
                if max_total_cost: self.budget_manager.max_total_cost = max_total_cost
        else:
            # Create local budget manager for components that need isolated tracking
            self.budget_manager = type('LocalBudget', (), {
                'total_tokens_used': 0,
                'total_cost': 0.0,
                'token_usage_log': [],
                'max_total_tokens': max_total_tokens,
                'max_total_cost': max_total_cost,
                'model_pricing': {
                    'deepseek-chat': {'input': 0.0014, 'output': 0.0028},
                    'claude-3-7-sonnet-20250219-all': {'input': 0.003, 'output': 0.015},
                    'claude-3-7-sonnet-20250219-low': {'input': 0.003, 'output': 0.015},
                    'claude-3-7-sonnet-20250219': {'input': 0.003, 'output': 0.015},
                    'gpt-4': {'input': 0.03, 'output': 0.06},
                    'gpt-3.5-turbo': {'input': 0.0015, 'output': 0.002}
                }
            })()
    
    
    @property
    def total_tokens_used(self):
        
        return self.budget_manager.total_tokens_used
    
    @property
    def total_cost(self):
        
        return self.budget_manager.total_cost
    
    @property
    def token_usage_log(self):
        
        return self.budget_manager.token_usage_log
    
    @property
    def max_total_tokens(self):
        
        return self.budget_manager.max_total_tokens
    
    @property
    def max_total_cost(self):
        
        return self.budget_manager.max_total_cost
    
    def calculate_token_cost(self, model_name, input_tokens, output_tokens):
        
        # Normalize model name for pricing lookup
        pricing_key = model_name
        if model_name.startswith('deepseek'):
            pricing_key = 'deepseek-chat'
        elif 'claude' in model_name.lower():
            pricing_key = 'claude-3-7-sonnet-20250219'
        elif 'gpt-4' in model_name.lower():
            pricing_key = 'gpt-4'
        elif 'gpt-3.5' in model_name.lower():
            pricing_key = 'gpt-3.5-turbo'
        
        pricing = self.budget_manager.model_pricing.get(pricing_key, {'input': 0.01, 'output': 0.02})  # Default pricing
        
        input_cost = (input_tokens / 1000.0) * pricing['input']
        output_cost = (output_tokens / 1000.0) * pricing['output']
        total_cost = input_cost + output_cost
        
        return total_cost, input_cost, output_cost
    
    def log_token_usage(self, model_name, input_tokens, output_tokens, cost, operation):
        
        usage_record = {
            'operation': operation,
            'model': model_name,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'total_tokens': input_tokens + output_tokens,
            'cost': cost,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        self.budget_manager.token_usage_log.append(usage_record)
        self.budget_manager.total_tokens_used += input_tokens + output_tokens
        self.budget_manager.total_cost += cost
        
        print(f"Token usage - Model: {model_name}, Operation: {operation}, Input: {input_tokens}, Output: {output_tokens}, Cost: ${cost:.4f}")
        print(f"Total tokens used: {self.budget_manager.total_tokens_used}, Total cost: ${self.budget_manager.total_cost:.4f}")
    
    def get_usage_summary(self):
        
        summary = {
            'total_tokens_used': self.budget_manager.total_tokens_used,
            'total_cost': self.budget_manager.total_cost,
        }
        
        # Add budget information if limits are set
        if hasattr(self.budget_manager, 'max_total_tokens') and self.budget_manager.max_total_tokens:
            summary.update({
                'max_total_tokens': self.budget_manager.max_total_tokens,
                'max_total_cost': self.budget_manager.max_total_cost,
                'tokens_remaining': self.budget_manager.max_total_tokens - self.budget_manager.total_tokens_used,
                'budget_remaining': self.budget_manager.max_total_cost - self.budget_manager.total_cost
            })
        
        return summary
    
    def check_budget_limits(self, estimated_input_tokens=0):
        
        if not hasattr(self.budget_manager, 'max_total_tokens') or not self.budget_manager.max_total_tokens:
            return True, "No budget limits set"
            
        estimated_cost = (estimated_input_tokens / 1000.0) * 0.01  # Conservative estimate
        
        if self.budget_manager.total_tokens_used + estimated_input_tokens > self.budget_manager.max_total_tokens:
            return False, f"Would exceed token limit ({self.budget_manager.total_tokens_used + estimated_input_tokens} > {self.budget_manager.max_total_tokens})"
        
        if self.budget_manager.total_cost + estimated_cost > self.budget_manager.max_total_cost:
            return False, f"Would exceed cost limit (${self.budget_manager.total_cost + estimated_cost:.4f} > ${self.budget_manager.max_total_cost})"
        
        return True, "Within budget limits"
    
    def abort_if_budget_exceeded(self, estimated_input_tokens=0, operation="operation"):
        
        can_proceed, message = self.check_budget_limits(estimated_input_tokens)
        if not can_proceed:
            raise BudgetExceededException(f"Budget limit exceeded during {operation}: {message}")
        return True
    
    def save_usage_log(self, filename=None, operation_name="operation"):
        
        if filename is None:
            filename = f'/tmp/{operation_name}_usage_log.json'
        
        usage_data = {
            'summary': self.get_usage_summary(),
            'detailed_log': self.budget_manager.token_usage_log
        }
        
        # Use JsonOperationHelper if available (for classes that inherit from it)
        if hasattr(self, 'save_json_file'):
            success = self.save_json_file(usage_data, filename)
            if success:
                print(f"{operation_name.capitalize()} usage log saved to: {filename}")
            else:
                print(f"Error saving {operation_name} usage log")
        else:
            # Fallback to direct JSON handling
            try:
                with open(filename, 'w') as f:
                    json.dump(usage_data, f, indent=2)
                print(f"{operation_name.capitalize()} usage log saved to: {filename}")
            except Exception as e:
                print(f"Error saving {operation_name} usage log: {e}")
    
    def print_usage_summary(self, operation_name="OPERATION"):
        
        final_summary = self.get_usage_summary()
        print(f"\n=== {operation_name.upper()} TOKEN USAGE SUMMARY ===")
        print(f"Total tokens used: {final_summary['total_tokens_used']}")
        print(f"Total cost: ${final_summary['total_cost']:.4f}")

class JsonOperationHelper:
    
    
    @staticmethod
    def save_json_file(data, file_path, indent=2):
        
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=indent, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error saving JSON file {file_path}: {e}")
            return False
    
    @staticmethod
    def load_json_file(file_path):
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading JSON file {file_path}: {e}")
            return None
    
    @staticmethod
    def parse_json_string(json_string):
        
        try:
            return json.loads(json_string)
        except json.JSONDecodeError as e:
            # print(f"Error parsing JSON string: {e}")
            # print(f"JSON string: {json_string}")
            return None

class FileOperationHelper:
    
    
    @staticmethod
    def read_file_content(file_path):
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return None
    
    @staticmethod
    def write_file_content(file_path, content):
        
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            print(f"Error writing file {file_path}: {e}")
            return False
    
    @staticmethod
    def find_line_number_in_file(file_path, target_line):
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Try exact match first
            for line_num, line in enumerate(lines, 1):
                if target_line.strip() == line.strip():
                    return line_num
            
            # Helper function to normalize PHP/HTML code for comparison
            def normalize_code_for_matching(code_line):
                
                import re
                
                # Extract PHP code blocks from the line
                php_blocks = []
                
                # Find all PHP code blocks (<?php ... ?> or <? ... ?>)
                php_pattern = r'<\?\s*(?:php\s*)?(.*?)\s*\?>'
                matches = re.findall(php_pattern, code_line, re.DOTALL | re.IGNORECASE)
                
                if matches:
                    # If PHP blocks found, concatenate all PHP content
                    php_content = ' '.join(matches)
                else:
                    # If no PHP tags found, check if it's pure PHP content (no HTML tags)
                    # If the line contains HTML tags but no PHP tags, return empty
                    if re.search(r'<[^?].*?>', code_line):
                        # Contains HTML tags but no PHP, return empty
                        php_content = ''
                    else:
                        # Assume it's pure PHP content without tags
                        php_content = code_line
                
                # Normalize whitespace: replace multiple spaces/tabs/newlines with single space
                normalized = re.sub(r'\s+', ' ', php_content.strip())
                
                return normalized
            
            # Try similarity matching with normalized content (0% threshold)
            from difflib import SequenceMatcher
            
            target_normalized = normalize_code_for_matching(target_line)
            best_match_line = None
            best_similarity = 0.0
            similarity_threshold = 0.0  # 0% threshold as requested
            
            for line_num, line in enumerate(lines, 1):
                line_normalized = normalize_code_for_matching(line.strip())
                if not line_normalized:  # Skip empty lines after normalization
                    continue
                
                # Calculate similarity using SequenceMatcher
                similarity = SequenceMatcher(None, target_normalized, line_normalized).ratio()
                
                # Update best match if this line has higher similarity
                if similarity > best_similarity and similarity >= similarity_threshold:
                    best_similarity = similarity
                    best_match_line = line_num
            
            if best_match_line:
                print(f"Found similar line with {best_similarity:.2%} similarity at line {best_match_line}")
                return best_match_line
            
            print(f"Could not find line '{target_line}' in file {file_path}")
            return None
            
        except Exception as e:
            print(f"Error finding line number: {e}")
            return None

class LLMApiHelper:
    
    
    def __init__(self):
        self.deepseek_api_key = 'Your key here'
        self.vapi_key = "Your key here"

    def get_client(self, model):
        
        import openai
        if model.startswith('deepseek'):
            return openai.Client(api_key=self.deepseek_api_key, base_url='https://api.deepseek.com/v1')
        else:
            return openai.Client(api_key=self.vapi_key, base_url='https://api.gpt.ge/v1')
    
    def extract_json_from_response(self, content):
        
        if '```json' in content:
            content = content.split('```json')[1].split('```')[0].strip()
        elif '```' in content:
            content = content.split('```')[1].strip()
        return content.strip()
    
    def estimate_tokens(self, text):
               return len(text) // 4

class ProgressTimer:
    
    def __init__(self, command_name):
        self.command_name = command_name
        self.start_time = None
        self.stop_event = threading.Event()
        self.timer_thread = None
    
    def start(self):
        
        self.start_time = time.time()
        self.stop_event.clear()
        print(f"Starting: {self.command_name}")
        self.timer_thread = threading.Thread(target=self._update_progress)
        self.timer_thread.daemon = True
        self.timer_thread.start()
    
    def stop(self):
        
        if self.timer_thread and self.timer_thread.is_alive():
            self.stop_event.set()
            self.timer_thread.join(timeout=1)
        elapsed = time.time() - self.start_time if self.start_time else 0
        formatted_time = self._format_time(elapsed)
        print(f"\r{self.command_name} - Completed! Total time: {formatted_time}")
        print()  # New line
    
    def _update_progress(self):
        
        # Wait 1 second before starting to show progress to avoid immediate 00:00:00
        time.sleep(1.0)
        while not self.stop_event.is_set():
            elapsed = time.time() - self.start_time
            formatted_time = self._format_time(elapsed)
            print(f"\r{self.command_name} - Elapsed: {formatted_time}", end="", flush=True)
            time.sleep(1.0)  # Update every 1 second
    
    def _format_time(self, seconds):
        
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def run_command_with_progress(cmd, command_name, cwd=None):
    
    timer = ProgressTimer(command_name)
    timer.start()
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, cwd=cwd)
        timer.stop()
        return result
    except subprocess.CalledProcessError as e:
        timer.stop()
        raise e


def map_targets_to_nodes(targets_df, nodes_df, nodes_df_dict):
    target_nodes = []

    for _, row in targets_df.iterrows():
        file_name, lineno = row[0].split(':')
        lineno = int(lineno)

        # Find the target file row
        try:
            file_row = nodes_df[(nodes_df['type'] == 'AST_TOPLEVEL') & (nodes_df['name'] == file_name) & (nodes_df['flags:string_array'] == 'TOPLEVEL_FILE')].iloc[0]
        except IndexError:
            print(f"Target {file_name}:{lineno} is not found.")
            continue
        # Find the target node
        condition = (nodes_df['lineno:int'] == lineno)
        try:
            target_node_ids = nodes_df.loc[file_row.name:].loc[condition]['id:int'].tolist()
        except IndexError:
            print(f"Target node {file_name}:{lineno} is not found.")
            continue
        # Find the next file row
        try:
            next_file_id = nodes_df.loc[file_row.name:].loc[(nodes_df['type'] == 'AST_TOPLEVEL') & (nodes_df['flags:string_array'] == 'TOPLEVEL_FILE')].iloc[1]['id:int']
        except IndexError:
            next_file_id = float('inf')
        # If the target node is not found, print error message
        if len(target_node_ids) and target_node_ids[0] >= next_file_id:
            print(f"Target node {file_name}:{lineno} is not found.")
            continue
        for target_node_id in target_node_ids:
            if target_node_id < next_file_id:
                target_nodes.append(target_node_id)

    print(f"Mapped provided {len(targets_df)} targets to {len(target_nodes)} possible nodes.")
    print(f"Target nodes: {target_nodes}")
    return target_nodes

def map_externals(nodes_df, nodes_df_dict, data_flow_origins, out_file_path):
    save_file = os.path.join(out_file_path, 'data_flow_origins.csv')
    data_flow_origins_copy = data_flow_origins.copy()
    super_globals_pattern = re.compile(r'_(GET|POST|REQUEST|COOKIE)')
    
    for node_id, origins in data_flow_origins_copy.items():
        for origin in origins:
            is_external = False
            # Find the origin node
            origin_node = nodes_df_dict.get(origin)
            if origin_node is None:
                continue
            # Find all nodes before or after the origin node and share the same lineno
            try:
                next_node_id = origin + 1
                next_node = nodes_df_dict.get(next_node_id)
                while origin_node['lineno:int'] == next_node['lineno:int']:
                    if super_globals_pattern.search(str(next_node['code'])):
                        is_external = True
                        break
                    next_node_id += 1
                    next_node = nodes_df_dict.get(next_node_id)
                    
                prev_node_id = origin - 1
                prev_node = nodes_df_dict.get(prev_node_id)
                while origin_node['lineno:int'] == prev_node['lineno:int']:
                    if super_globals_pattern.search(str(prev_node['code'])):
                        is_external = True
                        break
                    prev_node_id -= 1
                    prev_node = nodes_df_dict.get(prev_node_id)
            except IndexError:
                pass
            if not is_external:
                data_flow_origins[node_id].remove(origin)
                
    with open(save_file, 'w') as f:
        for key, values in data_flow_origins.items():
            if values:
                line = f"{key}\t{','.join(map(str, values))}\n"
                f.write(line)

def get_first_control_or_data_flow_predecessor(node, base_graph, ast, for_data_return=False):
    # Get the first control or data flow predecessor of the node
    result = None
    if node not in base_graph.nodes or for_data_return: # for data return, we need to find the predecessor, even if the node is already in icfg
        while result == None:
            try:
                pred = list(ast.predecessors(node))[0]
            except IndexError:
                break
            if pred in base_graph.nodes:
                result = pred
            else:
                node = pred
    else:
        result = node
    return result

def get_file_name_of_node(node_id, nodes_df_dict):
    node = nodes_df_dict.get(node_id)
    while node['flags:string_array'] != 'TOPLEVEL_FILE':
        node = nodes_df_dict.get(node['funcid:int'])
    return node['name']

def get_lineno_of_node(node_id, nodes_df_dict):
    node = nodes_df_dict.get(node_id)
    # print(node) # DEBUG
    try:
        return int(node['lineno:int'])
    except ValueError:
        return None
    
def get_funcid_of_node(node_id, nodes_df_dict):
    node = nodes_df_dict.get(node_id)
    if node is None:
        return None
    try:
        return int(node['funcid:int'])
    except ValueError:
        return None

def get_flags_of_node(node_id, nodes_df_dict):
    node = nodes_df_dict.get(node_id)
    if node is None:
        return None
    try:
        return node['flags:string_array']
    except KeyError:
        return None
    
def get_node_by_id(node_id, nodes_df_dict):
    # Get the node by its ID from the nodes_df_dict
    node = nodes_df_dict.get(node_id)
    if node is None:
        raise ValueError(f"Node with ID {node_id} not found in nodes_df_dict.")
    return node
    
def get_all_nodes_on_this_line(node_id, nodes_df_dict):
    all_nodes_on_this_line = set()
    base_node = nodes_df_dict.get(node_id)
    curr_node = base_node
    curr_node_id = node_id
    while curr_node['lineno:int'] == base_node['lineno:int']:
        all_nodes_on_this_line.add(curr_node_id)
        curr_node_id += 1
        curr_node = nodes_df_dict.get(curr_node_id)
    curr_node = base_node
    curr_node_id = node_id
    while curr_node['lineno:int'] == base_node['lineno:int']:
        all_nodes_on_this_line.add(curr_node_id)
        curr_node_id -= 1
        curr_node = nodes_df_dict.get(curr_node_id)
    return all_nodes_on_this_line

def safe_remove_files(directory, pattern):
    
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
    
    cleanup_operations = [
        ("/dev/shm/traces", "trace*.xt"),
        ("/dev/shm/coverages", "*.json"),
    ]
    
    for directory, pattern in cleanup_operations:
        safe_remove_files(directory, pattern)
    
    print("Coverage cleanup completed")

def extract_vulnerability_type_from_poc(poc_path):
    
    try:
        with open(poc_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Look for [TYPE] in the docstring
        lines = content.split('\n')
        for line in lines:
            if '[TYPE]' in line:
                # Extract text after [TYPE]
                type_part = line.split('[TYPE]')[-1].strip()
                return type_part if type_part else 'Unknown'
        
        return 'Unknown'
    except Exception as e:
        print(f"Warning: Could not extract vulnerability type from {poc_path}: {e}")
        return 'Unknown'
    
def restore_app_from_baks():
    
    if os.path.exists('/tmp/patch_bak.log'):
        with open('/tmp/patch_bak.log', 'r') as f:
            for line in f:
                line = line.strip()
                if os.path.exists(line):
                    os.unlink(line.split('.bak')[0])
                    # Restore the original file from the backup
                    shutil.copy(line, line.split('.bak')[0])
                    os.remove(line)
                    print(f"Restored {line.split('.bak')[0]} from backup {line}")
        os.remove('/tmp/patch_bak.log')
    else:
        print("No backup log found. Cannot restore original files.")

def touch_cc_switch(pos=True):
    
    if pos:
        with open('/enable_cc.php', 'r') as f:
            enable_cc_content = f.read()
        if enable_cc_content:
            enable_cc_content = enable_cc_content.replace('$do_cc = false;', '$do_cc = true;')
            print("Code coverage enabled")
        with open('/enable_cc.php', 'w') as f:
            f.write(enable_cc_content)
    else:
        # Disable code coverage
        with open('/enable_cc.php', 'r') as f:
            enable_cc_content = f.read()
        if enable_cc_content:
            enable_cc_content = enable_cc_content.replace('$do_cc = true;', '$do_cc = false;')
            print("Code coverage disabled")
        with open('/enable_cc.php', 'w') as f:
            f.write(enable_cc_content)

def init_dirs_files(args):
    
    if os.path.exists('/tmp/start_test.dat'):
        os.remove('/tmp/start_test.dat')
    if os.path.exists(args.instr_dir):
        shutil.rmtree(args.instr_dir)
        
    if os.path.exists('/dev/shm/coverages'):
        shutil.rmtree('/dev/shm/coverages')
    os.makedirs('/dev/shm/coverages', exist_ok=True)
    os.chmod('/dev/shm/coverages', 0o777)
        
    if os.path.exists('/dev/shm/traces'):
        shutil.rmtree('/dev/shm/traces')
    os.makedirs('/dev/shm/traces', exist_ok=True)
    os.chmod('/dev/shm/traces', 0o777)

    os.makedirs(args.instr_dir, exist_ok=True)

def extract_left_right_values_with_php_parser(slice_directory, poc_factory=None):
    
    print(f"\n--- Extracting left/right values from slice directory: {slice_directory} ---")
    
    import subprocess
    import json
    
    try:
        # Generate output file path
        output_file = os.path.join(os.path.dirname(__file__), 'request_data.json')
        
        # PHP script path
        php_script_path = os.path.join(os.path.dirname(__file__), 'extract_left_right_values.php')
        
        # Check if PHP script exists
        if not os.path.exists(php_script_path):
            print(f"✗ PHP script not found: {php_script_path}")
            return None
        
        # Get POC request data
        poc_request_data = {}
        if poc_factory:
            try:
                poc_request_data = poc_factory.get_poc_request_data()
                print(f"✓ Extracted POC request data:")
                print(f"  URL: {poc_request_data.get('url', 'N/A')}")
                print(f"  Method: {poc_request_data.get('method', 'N/A')}")
                print(f"  Params: {poc_request_data.get('params', {})}")
                print(f"  Crash fields: {poc_request_data.get('crash_fields', [])}")
            except Exception as e:
                print(f"⚠ Warning: Could not extract POC request data: {e}")
                poc_request_data = {}
        
        # Write POC request data to a temporary file for PHP script
        poc_data_file = os.path.join(os.path.dirname(__file__), 'poc_request_data.json')
        with open(poc_data_file, 'w') as f:
            json.dump(poc_request_data, f, indent=2)
        
        # Run PHP script
        print(f"Running PHP parser to extract left/right values...")
        print(f"PHP script: {php_script_path}")
        print(f"Slice directory: {slice_directory}")
        print(f"Output file: {output_file}")
        print(f"POC data file: {poc_data_file}")
        
        cmd = ['php', php_script_path, slice_directory, output_file, poc_data_file]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120  # 2-minute timeout
        )
        
        if result.returncode == 0:
            print(f"✓ Left/right value extraction completed successfully")
            print(f"✓ Output: {result.stdout.strip()}")
            
            # Verify the generated file
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    input_set_size = len(data.get('inputSet', []))
                    requests_count = len(data.get('requestsFound', {}))
                    print(f"✓ Generated request_data.json with {input_set_size} input items and {requests_count} requests")
                    
                    # Print some sample data
                    if data.get('inputSet'):
                        sample_inputs = data['inputSet'][:10]  # First 10 samples
                        print(f"✓ Sample input items: {sample_inputs}")
                
                return output_file
            else:
                print("✗ Failed to generate request_data.json file")
                return None
        else:
            print(f"✗ PHP parser execution failed:")
            print(f"  Return code: {result.returncode}")
            print(f"  STDOUT: {result.stdout}")
            print(f"  STDERR: {result.stderr}")
            return None
    
    except subprocess.TimeoutExpired:
        print("✗ PHP parser execution timed out")
        return None
    except Exception as e:
        print(f"✗ Error running PHP parser: {e}")
        return None

def format_patch_content(returned_patch):
    
    if not returned_patch:
        return ""
    
    import json
    # Return the patch as formatted JSON string
    return json.dumps(returned_patch, indent=2, ensure_ascii=False)