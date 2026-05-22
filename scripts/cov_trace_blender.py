import os
import json
import glob
import re
import subprocess
from collections import defaultdict
from datetime import datetime
from utils import *

class CovTraceBlender:
    def __init__(self, cov_dir, dest_dir, trace_dir):
        
        self.cov_dir = cov_dir
        self.dest_dir = dest_dir
        self.trace_dir = trace_dir
        self.main_data = {}
        self.sequence_dict = defaultdict(list)
        self.global_sequence = 1

    def parse_trace_file(self, trace_file):
        
        trace_data = defaultdict(dict)
        with open(trace_file, 'r', encoding='latin-1') as f:
            time_start = None
            for line in f:
                # Skip header lines and non-entry records
                if time_start is None and line.startswith('TRACE START'):
                    print(f"Processing line: {line.strip()}")
                    # Extract timestamp from TRACE START [2025-07-13 17:38:06.120820]
                    match = re.search(r'\[([\d-]+ [\d:]+\.[\d]+)\]', line)
                    if match:
                        timestamp_str = match.group(1)
                        # Convert to timestamp
                        dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
                        time_start = dt.timestamp()
                        # Add the time difference between current timezone and UTC
                        time_start += datetime.now().astimezone().utcoffset().total_seconds()
                    else:
                        time_start = 0.0
                    print(f"Time start: {time_start}")
                if line.startswith(('Version:', 'File format:', 'TRACE START', 'TRACE END')) or '\t' not in line:
                    continue
                
                fields = line.strip().split('\t')
                # Only process entry records (3rd field == '0')
                if len(fields) < 11 or fields[2] != '0':
                    continue

                # Extract core fields
                layer = int(fields[0])
                func_call = fields[5]
                file_path = fields[8]
                line_no = int(fields[9])
                is_internal = (fields[6] == '0')  # 0=internal, 1=user-defined
                
                # Skip excluded files
                if 'enable_cc.php' in file_path or 'clean.php' in file_path:
                    continue

                # Handle function arguments
                num_args = int(fields[10])
                args = fields[11:11+num_args] if len(fields) > 11 else []

                # Assign sequence number
                current_sequence = self.global_sequence
                self.global_sequence += 1
                
                # Store core metadata
                trace_data[(file_path, line_no, current_sequence)] = {
                    'layer': layer,
                    'is_built_in': is_internal,
                    'func_call': func_call,
                    'sequence': current_sequence,
                    'timestamp': time_start + float(fields[3]) if time_start is not None else float(fields[3]),  # Absolute timestamp
                }
                self.sequence_dict[(file_path, line_no)].append(current_sequence)

                # Extract included files for include/require functions
                if func_call in ['include', 'include_once', 'require', 'require_once']:
                    included_file = fields[7]
                    trace_data[(file_path, line_no, current_sequence)]['included_file'] = included_file
                
                # Record main function data
                if func_call == '{main}':
                    self.main_data[current_sequence] = {
                        'file_path': file_path,
                        'line_no': line_no,
                        'sequence': current_sequence,
                        'timestamp': time_start + float(fields[3]) if time_start is not None else float(fields[3]),
                    }
                    
        return trace_data

    def filter_executed_lines(self, coverage_data):
        
        return {
            file: {line: val for line, val in lines.items() if val >= 1}
            for file, lines in coverage_data.items()
        }

    def process_coverage_file(self):
        # Find all coverage files
        coverage_files = glob.glob(os.path.join(self.cov_dir, "*.cc.json"))
        if not coverage_files:
            raise FileNotFoundError(f"No coverage files found in {self.cov_dir}")
        
        # Extract timestamps and find the latest file
        file_timestamps = []
        for file_path in coverage_files:
            filename = os.path.basename(file_path)
            # Extract timestamp from filename format: ..._timestamp.cc.json
            parts = filename.split('_')
            if len(parts) < 2:
                print(f"Skipping file with invalid format: {filename}")
                continue
                
            timestamp_str = parts[-1].split('.')[0]
            try:
                timestamp = int(timestamp_str)
                file_timestamps.append((file_path, timestamp))
            except ValueError:
                print(f"Skipping file with invalid timestamp: {filename}")
        
        if not file_timestamps:
            raise ValueError("No valid timestamp found in coverage files")
        
        # Find the latest file and its timestamp
        latest_file, latest_timestamp = max(file_timestamps, key=lambda x: x[1])

        print(f"Processing {len(coverage_files)} coverage files (latest: {latest_timestamp})")

        # Merge coverage data from files in the time window
        merged_coverage = {}
        for coverage_file in coverage_files:
            try:
                with open(coverage_file, "r") as f:
                    coverage_data = json.load(f)
                
                # Merge coverage data
                for file_path, lines in coverage_data.items():
                    if file_path not in merged_coverage:
                        merged_coverage[file_path] = {}
                    
                    for line_no, count in lines.items():
                        merged_coverage[file_path][line_no] = merged_coverage[file_path].get(line_no, 0) + count
            
            except Exception as e:
                print(f"Error processing {coverage_file}: {str(e)}")
        
        # Skip if no coverage data
        if not merged_coverage:
            print("No coverage data to process")
            return
        
        # Filter coverage data
        filtered_data = self.filter_executed_lines(merged_coverage)
        
        # Process trace file (use the latest one)
        trace_files = glob.glob(os.path.join(self.trace_dir, "trace.*.xt"))
        if not trace_files:
            print("Warning: No trace files found")
            trace_data = {}
        else:
            # merge trace data from tall trace files
            trace_data = {}
            print(f"Processing {len(trace_files)} trace files")
            for trace_file in trace_files:
                print(f"Processing trace file: {trace_file}, timestamp: {os.path.getmtime(trace_file)}")
                trace_data.update(self.parse_trace_file(trace_file))

        # Merge trace info into coverage data
        optimized_data = {}

        main_data = {'main': self.main_data}

        for file_path, lines in filtered_data.items():
            if 'enable_cc.php' in file_path or 'clean.php' in file_path:
                continue
            optimized_lines = {}
            for line_no in lines:
                line_no_int = int(line_no)
                sequences = self.sequence_dict.get((file_path, line_no_int), [])
                if not sequences:
                    optimized_lines[f"{line_no}, {-1}"] = {'layer': -1, 'is_built_in': '', 'sequence': -1, 'func_call': ''}
                else:
                    for seq in sequences:
                        trace_info = trace_data.get(
                            (file_path, line_no_int, seq),
                            {'layer': -1, 'is_built_in': '', 'sequence': -1, 'func_call': ''}
                        )
                        optimized_lines[f"{line_no}, {seq}"] = trace_info
            optimized_data[file_path] = optimized_lines

        # Collect execution order information
        execution_order = []
        for file_path, lines in optimized_data.items():
            for lineno_and_seq, info in lines.items():
                lineno, seq = lineno_and_seq.split(', ')
                if info['sequence'] != -1:
                    execution_order.append({
                        'sequence': seq,
                        'filename': file_path,
                        'lineno': lineno,
                    })
        
        # Sort execution order by sequence number
        execution_order.sort(key=lambda x: int(x['sequence']))
        
        # Create final data structure with execution order first
        final_data = {"execution_order": execution_order}
        optimized_data = {"detailed_info": optimized_data}
        final_data.update(optimized_data)
        final_data.update(main_data)

        # Save optimized data
        os.makedirs(self.dest_dir, exist_ok=True)
        dest_file = os.path.join(self.dest_dir, os.path.basename(latest_file).replace('.cc.json', '_optimized.json'))
        
        def convert_sets(obj):
            if isinstance(obj, set):
                return list(obj)
            elif isinstance(obj, dict):
                return {k: convert_sets(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_sets(item) for item in obj]
            return obj
        
        final_data_converted = convert_sets(final_data)
        
        with open(dest_file, "w") as f:
            json.dump(final_data_converted, f, indent=4)
        print(f"Optimized coverage data saved to {dest_file}")
        
        # Cleanup all coverage files
        # cleanup_coverage_files()
            
    def get_php_internal_functions(self):
        
        # Fallback list of common PHP 7.4+ internal functions
        built_in_functions_fallback = {
            # Basic functions
            'array', 'echo', 'empty', 'eval', 'exit', 'die', 'isset', 'list', 'print', 'unset',

            # String processing
            'addcslashes', 'addslashes', 'bin2hex', 'chop', 'chr', 'chunk_split', 'convert_uudecode',
            'convert_uuencode', 'count_chars', 'crc32', 'crypt', 'explode', 'fprintf', 'get_html_translation_table',
            'hebrev', 'hebrevc', 'hex2bin', 'html_entity_decode', 'htmlentities', 'htmlspecialchars_decode',
            'htmlspecialchars', 'implode', 'join', 'lcfirst', 'levenshtein', 'localeconv', 'ltrim', 'md5', 'md5_file',
            'metaphone', 'money_format', 'nl_langinfo', 'nl2br', 'number_format', 'ord', 'parse_str', 'print_r', 'printf',
            'quoted_printable_decode', 'quoted_printable_encode', 'quotemeta', 'rtrim', 'setlocale', 'sha1', 'sha1_file',
            'similar_text', 'soundex', 'sprintf', 'sscanf', 'str_getcsv', 'str_ireplace', 'str_pad', 'str_repeat', 'str_replace',
            'str_rot13', 'str_shuffle', 'str_split', 'str_word_count', 'strcasecmp', 'strchr', 'strcmp', 'strcoll', 'strcspn',
            'strip_tags', 'stripcslashes', 'stripos', 'stripslashes', 'stristr', 'strlen', 'strnatcasecmp', 'strnatcmp',
            'strncasecmp', 'strncmp', 'strpbrk', 'strpos', 'strrchr', 'strrev', 'strripos', 'strrpos', 'strspn', 'strstr',
            'strtok', 'strtolower', 'strtoupper', 'strtr', 'substr', 'substr_compare', 'substr_count', 'substr_replace',
            'trim', 'ucfirst', 'ucwords', 'vfprintf', 'vprintf', 'vsprintf', 'wordwrap',

            # Array processing
            'array_change_key_case', 'array_chunk', 'array_column', 'array_combine', 'array_count_values', 'array_diff',
            'array_diff_assoc', 'array_diff_key', 'array_diff_uassoc', 'array_diff_ukey', 'array_fill', 'array_fill_keys',
            'array_filter', 'array_flip', 'array_intersect', 'array_intersect_assoc', 'array_intersect_key', 'array_intersect_uassoc',
            'array_intersect_ukey', 'array_key_exists', 'array_key_first', 'array_key_last', 'array_keys', 'array_map',
            'array_merge', 'array_merge_recursive', 'array_multisort', 'array_pad', 'array_pop', 'array_product', 'array_push',
            'array_rand', 'array_reduce', 'array_replace', 'array_replace_recursive', 'array_reverse', 'array_search',
            'array_shift', 'array_slice', 'array_splice', 'array_sum', 'array_udiff', 'array_udiff_assoc', 'array_udiff_uassoc',
            'array_uintersect', 'array_uintersect_assoc', 'array_uintersect_uassoc', 'array_unique', 'array_unshift',
            'array_values', 'array_walk', 'array_walk_recursive', 'arsort', 'asort', 'compact', 'count', 'current', 'each',
            'end', 'extract', 'in_array', 'key', 'krsort', 'ksort', 'list', 'natcasesort', 'natsort', 'next', 'pos', 'prev',
            'range', 'reset', 'rsort', 'shuffle', 'sizeof', 'sort', 'uasort', 'uksort', 'usort',

            # File system
            'basename', 'chgrp', 'chmod', 'chown', 'clearstatcache', 'copy', 'delete', 'dirname', 'disk_free_space', 'disk_total_space',
            'diskfreespace', 'fclose', 'feof', 'fflush', 'fgetc', 'fgetcsv', 'fgets', 'fgetss', 'file_exists', 'file_get_contents',
            'file_put_contents', 'file', 'fileatime', 'filectime', 'filegroup', 'fileinode', 'filemtime', 'fileowner', 'fileperms',
            'filesize', 'filetype', 'flock', 'fnmatch', 'fopen', 'fpassthru', 'fputcsv', 'fputs', 'fread', 'fscanf', 'fseek',
            'fstat', 'ftell', 'ftruncate', 'fwrite', 'glob', 'is_dir', 'is_executable', 'is_file', 'is_link', 'is_readable',
            'is_uploaded_file', 'is_writable', 'is_writeable', 'lchgrp', 'lchown', 'link', 'linkinfo', 'lstat', 'mkdir', 'move_uploaded_file',
            'parse_ini_file', 'parse_ini_string', 'pathinfo', 'pclose', 'popen', 'readfile', 'readlink', 'realpath_cache_get',
            'realpath_cache_size', 'realpath', 'rename', 'rewind', 'rmdir', 'set_file_buffer', 'stat', 'symlink', 'tempnam',
            'tmpfile', 'touch', 'umask', 'unlink',

            # Date and time
            'checkdate', 'date_add', 'date_create_from_format', 'date_create', 'date_date_set', 'date_default_timezone_get',
            'date_default_timezone_set', 'date_diff', 'date_format', 'date_get_last_errors', 'date_interval_create_from_date_string',
            'date_interval_format', 'date_isodate_set', 'date_modify', 'date_offset_get', 'date_parse_from_format', 'date_parse',
            'date_sub', 'date_sun_info', 'date_sunrise', 'date_sunset', 'date_time_set', 'date_timestamp_get', 'date_timestamp_set',
            'date_timezone_get', 'date_timezone_set', 'date', 'getdate', 'gettimeofday', 'gmdate', 'gmmktime', 'gmstrftime',
            'idate', 'localtime', 'microtime', 'mktime', 'strftime', 'strptime', 'strtotime', 'time', 'timezone_abbreviations_list',
            'timezone_identifiers_list', 'timezone_location_get', 'timezone_name_from_abbr', 'timezone_name_get',
            'timezone_offset_get', 'timezone_open', 'timezone_transitions_get', 'timezone_version_get',

            # Database
            'mysqli_affected_rows', 'mysqli_autocommit', 'mysqli_begin_transaction', 'mysqli_change_user', 'mysqli_character_set_name',
            'mysqli_close', 'mysqli_commit', 'mysqli_connect_errno', 'mysqli_connect_error', 'mysqli_connect', 'mysqli_data_seek',
            'mysqli_debug', 'mysqli_dump_debug_info', 'mysqli_errno', 'mysqli_error_list', 'mysqli_error', 'mysqli_fetch_all',
            'mysqli_fetch_array', 'mysqli_fetch_assoc', 'mysqli_fetch_field_direct', 'mysqli_fetch_field', 'mysqli_fetch_fields',
            'mysqli_fetch_lengths', 'mysqli_fetch_object', 'mysqli_fetch_row', 'mysqli_field_count', 'mysqli_field_seek',
            'mysqli_field_tell', 'mysqli_free_result', 'mysqli_get_charset', 'mysqli_get_client_info', 'mysqli_get_client_stats',
            'mysqli_get_client_version', 'mysqli_get_connection_stats', 'mysqli_get_host_info', 'mysqli_get_proto_info',
            'mysqli_get_server_info', 'mysqli_get_server_version', 'mysqli_info', 'mysqli_init', 'mysqli_insert_id',
            'mysqli_kill', 'mysqli_more_results', 'mysqli_multi_query', 'mysqli_next_result', 'mysqli_num_fields',
            'mysqli_num_rows', 'mysqli_options', 'mysqli_ping', 'mysqli_poll', 'mysqli_prepare', 'mysqli_query', 'mysqli_real_connect',
            'mysqli_real_escape_string', 'mysqli_real_query', 'mysqli_reap_async_query', 'mysqli_refresh', 'mysqli_rollback',
            'mysqli_select_db', 'mysqli_set_charset', 'mysqli_set_local_infile_default', 'mysqli_set_local_infile_handler',
            'mysqli_sqlstate', 'mysqli_ssl_set', 'mysqli_stat', 'mysqli_stmt_init', 'mysqli_store_result', 'mysqli_thread_id',
            'mysqli_thread_safe', 'mysqli_use_result', 'mysqli_warning_count',

            # Other common
            'json_decode', 'json_encode', 'json_last_error_msg', 'json_last_error', 'session_start', 'session_id', 'session_destroy',
            'header', 'setcookie', 'headers_sent', 'http_response_code', 'password_hash', 'password_verify', 'password_needs_rehash',
            'random_bytes', 'random_int', 'error_reporting', 'trigger_error', 'set_error_handler', 'restore_error_handler',
            'set_exception_handler', 'restore_exception_handler', 'debug_backtrace', 'debug_print_backtrace', 'gc_collect_cycles',
            'gc_enable', 'gc_disable', 'gc_enabled', 'class_exists', 'interface_exists', 'trait_exists', 'method_exists',
            'property_exists', 'function_exists', 'get_class', 'get_parent_class', 'is_a', 'is_subclass_of', 'get_called_class',
            'get_class_methods', 'get_class_vars', 'get_object_vars', 'get_declared_classes', 'get_declared_interfaces',
            'get_declared_traits', 'get_defined_functions', 'get_defined_vars', 'get_resource_type', 'get_resources',
            'extension_loaded', 'get_loaded_extensions', 'get_defined_constants', 'get_included_files', 'get_required_files',
            'register_shutdown_function', 'register_tick_function', 'unregister_tick_function', 'highlight_file', 'highlight_string',
            'php_strip_whitespace', 'show_source', 'php_check_syntax', 'phpinfo', 'phpversion', 'phpcredits', 'php_sapi_name',
            'php_uname', 'php_ini_scanned_files', 'php_ini_loaded_file', 'putenv', 'getenv', 'memory_get_usage', 'memory_get_peak_usage',
            'version_compare', 'zend_version', 'func_get_args', 'func_get_arg', 'func_num_args', 'get_cfg_var', 'get_current_user',
            'get_defined_constants', 'get_extension_funcs', 'get_include_path', 'get_magic_quotes_gpc', 'get_magic_quotes_runtime',
            'get_meta_tags', 'get_mygid', 'get_myinode', 'get_mypid', 'get_myuid', 'get_required_files', 'get_resources', 'getenv',
            'getlastmod', 'getmygid', 'getmyinode', 'getmypid', 'getmyuid', 'getopt', 'getrusage', 'ini_get_all', 'ini_get',
            'ini_restore', 'ini_set', 'main', 'memory_get_peak_usage', 'memory_get_usage', 'php_ini_scanned_files', 'php_logo_guid',
            'php_sapi_name', 'php_uname', 'phpcredits', 'phpinfo', 'phpversion', 'putenv', 'restore_include_path', 'set_include_path',
            'set_time_limit', 'sys_get_temp_dir', 'version_compare', 'zend_logo_guid', 'zend_thread_id', 'zend_version',

            # Special structures (pseudo functions)
            'include', 'include_once', 'require', 'require_once'
        }

        cmd = ['php', '-r', 'echo json_encode(get_defined_functions()["internal"]);']

        try:
            # Compatible with Python 3.6
            result = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,  # Replaces capture_output=True
                stderr=subprocess.PIPE,
                universal_newlines=True  # Replaces text=True
            )
            return set(json.loads(result.stdout))
        except Exception as e:
            print(f"Dynamic fetch failed: {str(e)}, using static built-in function list")
            return built_in_functions_fallback  # Fallback to static list

    def get_php_internal_classes(self):
        
        
        php_script = """
            $classes = array_filter(
            array_merge(get_declared_classes(), get_declared_interfaces()),
                        function($name) {
                            $ref = new ReflectionClass($name);
                            return $ref->isInternal();
                        }
            );

            echo json_encode(array_values($classes));
            """

        # Static fallback list (common PHP 7.4+ built-in classes)
        built_in_classes_fallback = {
            # Core classes
            'stdClass', 'Exception', 'ErrorException', 'Closure', 'Generator', 'DateTime', 'DateTimeImmutable', 'DateTimeZone',
            'DateInterval', 'DatePeriod', 'LibXMLError', 'SQLite3', 'SQLite3Stmt', 'SQLite3Result', 'Phar', 'PharData', 'PharException',
            'Reflection', 'ReflectionClass', 'ReflectionZendExtension', 'ReflectionExtension', 'ReflectionFunction', 'ReflectionFunctionAbstract',
            'ReflectionMethod', 'ReflectionObject', 'ReflectionParameter', 'ReflectionProperty', 'ReflectionType', 'ReflectionNamedType',
            'ReflectionUnionType', 'ReflectionGenerator', 'ReflectionAttribute',

            # SPL classes
            'ArrayObject', 'ArrayIterator', 'RecursiveArrayIterator', 'CachingIterator', 'CallbackFilterIterator', 'DirectoryIterator',
            'FilesystemIterator', 'RecursiveDirectoryIterator', 'FilterIterator', 'GlobIterator', 'InfiniteIterator', 'IteratorIterator',
            'LimitIterator', 'MultipleIterator', 'NoRewindIterator', 'ParentIterator', 'RecursiveCachingIterator', 'RecursiveCallbackFilterIterator',
            'RecursiveFilterIterator', 'RecursiveIteratorIterator', 'RecursiveTreeIterator', 'SeekableIterator', 'SplFileInfo', 'SplFileObject',
            'SplTempFileObject', 'SplDoublyLinkedList', 'SplFixedArray', 'SplHeap', 'SplMaxHeap', 'SplMinHeap', 'SplPriorityQueue',
            'SplQueue', 'SplStack', 'SplObjectStorage',

            # Database-related classes
            'mysqli', 'mysqli_stmt', 'mysqli_result', 'mysqli_driver', 'mysqli_warning', 'PDO', 'PDOStatement', 'PDOException',
            'PDORow', 'PDO_SQLite', 'MongoDB\\Driver\\Manager', 'Redis', 'RedisArray', 'RedisCluster',

            # Other common classes
            'ZipArchive', 'DOMDocument', 'DOMNode', 'DOMElement', 'SimpleXMLElement', 'XMLReader', 'XMLWriter', 'XSLTProcessor',
            'SoapClient', 'SoapServer', 'JsonSerializable', 'SessionHandler', 'SessionHandlerInterface', 'Throwable', 'Traversable',
            'Iterator', 'IteratorAggregate', 'Serializable', 'Countable', 'ArrayAccess', 'DateTimeInterface', 'JsonException'
        }
        
        cmd = ['php', '-r', php_script]
        
        try:
            result = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            if result.stderr:
                print(f"PHP Error: {result.stderr.strip()}")
                
            return set(json.loads(result.stdout))
            
        except Exception as e:
            print(f"Dynamic fetch failed: {str(e)}, using static built-in class list")
            return built_in_classes_fallback  # Fallback to static list

if __name__ == "__main__":
    SOURCE_DIR = "/dev/shm/coverages"
    DEST_DIR = "/tmp/xdebug"
    TRACE_DIR = "/dev/shm/traces/"

    blender = CovTraceBlender(SOURCE_DIR, DEST_DIR, TRACE_DIR)
    try:
        blender.process_coverage_file()
    except Exception as e:
        print(f"Processing error: {str(e)}")
        raise
