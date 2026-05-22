import os
import glob
import json
import re
import argparse
from csv_manager import CSVManager
from collections import defaultdict
import pandas as pd
import math
import subprocess
import time
import shutil
from utils import run_command_with_progress, ProgressTimer

class CodeAssembler:
    def __init__(self, ori_app_dir, out_dir):
        self.ori_app_dir = ori_app_dir
        self.app_parent_dir = '/' + '/'.join(ori_app_dir[:-1])
        self.json_dir = '/tmp/xdebug'
        self.out_dir = out_dir
        self.nodes_df = None
        self.rels_df = None
        self.nodes_df_dict = None
        self.execution_order = []
        self.detailed_info = {}
        self.main_info = {}
        self.assembled_code_lines = []
        self.has_open_tag = False
        self.max_depth = 100
        self._file_cache = {}
        self.files_and_lines = defaultdict(list)  # {file: [code_lines]}
        self.include_stat_locations_and_namelist = defaultdict(set)
        self.added_items = defaultdict(set)
        self.registered_full_names = set()
        self.php_internal_classes = self._get_php_internal_classes()
        self.files_and_class_method_funcs_within = defaultdict(lambda: {'functions': set(), 'classes': defaultdict(lambda: {'static_methods': set(), 'instance_methods': set()})})
        self.files_and_classes_on_inheritance_chain = defaultdict(lambda: {'classes': defaultdict(lambda: {'static_methods': set(), 'instance_methods': set()})})
        self.files_and_classes_on_inheritance_chain_root = defaultdict(lambda: {'classes': defaultdict(lambda: {'static_methods': set(), 'instance_methods': set(), 'child_classes': set()})})
        self.executed_user_funcs = {
            'functions': set(),
            'classes': defaultdict(lambda: {'static_methods': set(), 'instance_methods': set()})
        }
        self.class_inheritance_chain = defaultdict(list) # {(class_id, class_name): [(parent_class_id, parent_class_name), ...]}
        self.class_parent_classes = defaultdict(set) # {(class_id, class_name): [parent_class_id, parent_class_name, filename), ...]}
        self.class_child_classes = defaultdict(set) # {(class_id, class_name): [child_class_id, child_class_name, filename), ...]}

    def _check_and_add_item(self, item_type, identifier):
        
        if identifier in self.added_items[item_type]:
            # print(f"[Duplicate] {item_type.capitalize()} '{identifier}' exists. Skipping.")
            return False
        self.added_items[item_type].add(identifier)
        return True

    def _get_name_space_from_nodes_df(self, node):
        name_space = node['namespace']
        if isinstance(name_space, str):
            name_space = name_space + '\\'
        else:
            name_space = ''
        return name_space

    def _find_file_definitions(self, file_path):
        
        file_node = self._find_toplevel_file_node_by_filename(file_path)
        if file_node is None:
            return []

        definitions = []
        file_id = file_node['id:int']
        next_file_node = self._find_next_toplevel_node(file_id)
        next_file_id = next_file_node['id:int'] if next_file_node is not None else None

        # Find all child nodes of the file
        file_children = self.nodes_df[
            (self.nodes_df['id:int'] > file_id) &
            (self.nodes_df['id:int'] < next_file_id if next_file_id else True)
        ]

        func_nodes = file_children[file_children['type'] == 'AST_FUNC_DECL']
        class_nodes = file_children[file_children['type'] == 'AST_CLASS']
        method_nodes = file_children[file_children['type'] == 'AST_METHOD']

        # Process different definition types
        for _, node in func_nodes.iterrows():
            definitions.append(('function', self._get_name_space_from_nodes_df(node) + node['name']))
        for _, node in class_nodes.iterrows():
            definitions.append(('class', self._get_name_space_from_nodes_df(node) + node['name']))
        for _, node in method_nodes.iterrows():
            class_name = self._get_name_space_from_nodes_df(node) + node['classname']
            method_name = node['name']
            if 'MODIFIER_STATIC' in node['flags:string_array']:
                definitions.append(('method', f"{class_name}::{method_name}"))
            else:
                definitions.append(('method', f"{class_name}->{method_name}"))

        return definitions

    def _register_file_definitions(self, file_path):
        
        for def_type, identifier in self._find_file_definitions(file_path):
            self._check_and_add_item(def_type, identifier)
            self.registered_full_names.add(identifier)
            self._categorize_and_record_registered_functions(def_type, file_path, identifier)
            # print(f"Registered {def_type}: {identifier} from {file_path}")

    def find_latest_file(self, directory, pattern):
        files = glob.glob(os.path.join(directory, pattern))
        if not files:
            raise FileNotFoundError(f"No files found in {directory} matching {pattern}")
        return max(files, key=os.path.getmtime)

    def load_data(self, json_dir, csv_working_dir):
        json_file = self.find_latest_file(json_dir, "*.json")
        with open(json_file, 'r') as f:
            print(f"Loading data from {json_file}...")
            data = json.load(f)
            self.execution_order = sorted(
                data.get("execution_order", []),
                key=lambda x: x["sequence"]
            )
            self.detailed_info = data.get("detailed_info", {})
            self.main_info = data.get("main", {})

        csv_manager = CSVManager(csv_working_dir)
        nodes_df, rels_df, _, _ = csv_manager.read_csvs(skip_targets=True)
        self.nodes_df = nodes_df
        self.rels_df = rels_df
        self.nodes_df_dict = nodes_df.set_index('id:int').to_dict('index')

    def _find_toplevel_file_node_by_filename(self, filename):
        filtered = self.nodes_df[
            (self.nodes_df['flags:string_array'] == 'TOPLEVEL_FILE') &
            (self.nodes_df['name'].apply(lambda x: isinstance(x, str) and x in filename))
        ]
        return None if filtered.empty else filtered.iloc[0]

    def _find_next_toplevel_node(self, current_node_id):
        next_nodes = self.nodes_df[
            (self.nodes_df['type'] == 'AST_TOPLEVEL') &
            (self.nodes_df['flags:string_array'] == 'TOPLEVEL_FILE') &
            (self.nodes_df['id:int'] > current_node_id)
        ]
        return None if next_nodes.empty else next_nodes.iloc[0]
    
    def _find_previous_toplevel_node(self, current_node_id):
        previous_nodes = self.nodes_df[
            (self.nodes_df['type'] == 'AST_TOPLEVEL') &
            (self.nodes_df['flags:string_array'] == 'TOPLEVEL_FILE') &
            (self.nodes_df['id:int'] < current_node_id)
        ]
        return None if previous_nodes.empty else previous_nodes.iloc[0]
    
    def _map_specific_node_type_in_current_file(self, node_type, current_file_id, next_file_id):
        
        return self.nodes_df[
            (self.nodes_df['type'] == node_type) &
            (self.nodes_df['id:int'] >= current_file_id) &
            (self.nodes_df['id:int'] < next_file_id)
        ]

    def _find_nodes_by_lineno(self, lineno, file_id, next_file_id):
        
        lineno = int(lineno)
        return self.nodes_df[
            (self.nodes_df['id:int'] >= file_id) &
            (self.nodes_df['id:int'] < next_file_id) &
            (self.nodes_df['lineno:int'] == lineno)
        ]

    def _split_namespace_and_identifier(self, full_name):
        if '\\' in full_name:
            namespace, identifier = full_name.rsplit('\\', 1)
            return namespace, identifier
        return '', full_name
    
    def _find_class_method_by_names(self, full_name):
        if '::' in full_name:
            class_name, method_name = full_name.split('::')
        else:
            class_name, method_name = full_name.split('->')
        
        name_space, class_name = self._split_namespace_and_identifier(class_name)
        # print(f"Namespace: {name_space}, Class name: {class_name}") if name_space else None
        
        classes = self.nodes_df[
            (self.nodes_df['type'].isin(['AST_CLASS'])) &
            (self.nodes_df['name'] == class_name) &
            (self.nodes_df['namespace'] == name_space if name_space else True)
        ]

        if not classes.empty:
            # Check class inheritance
            inherited_chain = []
            current_classes = classes
            while not current_classes.empty and len(inherited_chain) < self.max_depth:
                if len(current_classes) > 1:
                    pass # difficult here
                        
                else:
                    class_node = current_classes.iloc[0]
                    inherited_chain.append((class_node['id:int'], class_node['name']))
                    methods = self.nodes_df[
                        (self.nodes_df['type'].isin(['AST_METHOD'])) &
                        (self.nodes_df['name'] == method_name) &
                        (self.nodes_df['classname'] == class_node['name'])
                    ]
                    if not methods.empty:
                        break
                    ast_name_string_node = self.nodes_df_dict[class_node['id:int'] + 2]
                    if ast_name_string_node['type'] == 'string' and ast_name_string_node['code'] != class_name:
                        parent_class_name = ast_name_string_node['code']
                        parent_classes = self.nodes_df[
                            (self.nodes_df['type'].isin(['AST_CLASS'])) &
                            (self.nodes_df['name'] == parent_class_name)
                        ]
                        current_classes = parent_classes
                    else:
                        break
            print(f"Class inheritance chain for {(class_name, class_node['id:int'])}:\n{inherited_chain}\n") if len(inherited_chain) > 1 else None
            self.class_inheritance_chain[(class_name, class_node['id:int'])] = inherited_chain
        elif class_name == 'Closure' or 'closure:' in method_name:
            # TODO: Handle closures
            print(f"Closure found: {full_name}")
            return None, None
        else:
            print(f"Class not found: {class_name}")
            return None, None
            
        if methods.empty:
            print(f"Method not found: {class_name}::{method_name}")
            print(f"Classes: {classes}")
            print(f"Methods: {methods}")
            return None, None

        return classes, methods

    def _get_php_internal_classes(self):
        

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

    def _find_class_method_by_names(self, full_name, filename):
        # print(f"\nFinding class and method for: {full_name}")
        inherited = False
        is_static = False
        if '::' in full_name:
            class_name, method_name = full_name.split('::')
            is_static = True
        else:
            class_name, method_name = full_name.split('->')
        
        namespace, class_name = self._split_namespace_and_identifier(class_name)
        
        # Find initial candidate classes
        classes = self.nodes_df[
            (self.nodes_df['type'] == 'AST_CLASS') &
            (self.nodes_df['name'] == class_name) &
            (self.nodes_df['namespace'] == namespace if namespace else True)
        ]
        if '{closure:' in method_name:
            print(f"Closure found: {full_name}")
            return inherited, None, None
        if classes.empty:
            if class_name == 'Closure':
                print(f"Closure found: {full_name}")
                return inherited, None, None
            else:
                print(f"Class not found: {class_name}")
                return inherited, None, None
        
        # Recursively find inheritance chain
        inherited_chain = self._find_inheritance_chain(classes, [], self.max_depth, method_name)
        
        if inherited_chain is None:
            print(f"Method not found: {full_name}, initial class: {class_name}, id: {classes.iloc[0]['id:int']}")
            return inherited, None, None
        # Save inheritance chain
        final_class_id = inherited_chain[-1][0]
        # If the final class is a built-in class, return, but since it's a valid result, return True and a placeholder
        if final_class_id == -1:
            place_holder = 1
            return True, place_holder, place_holder
        first_class_id = inherited_chain[0][0]
        self.class_inheritance_chain[(class_name, first_class_id)] = inherited_chain
        last_class_file_node = self._find_previous_toplevel_node(inherited_chain[0][0])
        last_class_filename = last_class_file_node['name'] if last_class_file_node is not None else None
        self.class_parent_classes[inherited_chain[0]].add(
            (inherited_chain[0][0], inherited_chain[0][1], last_class_filename)
        )
        self.class_child_classes[inherited_chain[-1]].add(
            (inherited_chain[-1][0], inherited_chain[-1][1], filename)
        )
        
        # Get the final class and method
        final_class = self.nodes_df[self.nodes_df['id:int'] == final_class_id].iloc[0]
        methods = self.nodes_df[
            (self.nodes_df['type'] == 'AST_METHOD') &
            (self.nodes_df['name'] == method_name) &
            (self.nodes_df['classname'] == final_class['name'])
        ]
        final_method = methods.iloc[0]
        if len(inherited_chain) > 1:
            # print('inherited_root', inherited_chain[-1])
            inherited = True
            for inherited_class_id, inherited_class_name in inherited_chain[1:]:
                if is_static:
                    self.files_and_classes_on_inheritance_chain[filename]['classes'][inherited_class_name]['static_methods'].add(method_name)
                else:
                    self.files_and_classes_on_inheritance_chain[filename]['classes'][inherited_class_name]['instance_methods'].add(method_name)
            root_class_id, root_class_name = inherited_chain[-1]
            self.files_and_classes_on_inheritance_chain_root[filename]['classes'][root_class_name]['child_classes'].add(class_name)
            if is_static:
                self.files_and_classes_on_inheritance_chain_root[filename]['classes'][root_class_name]['static_methods'].add(method_name)
            else:
                self.files_and_classes_on_inheritance_chain_root[filename]['classes'][root_class_name]['instance_methods'].add(method_name)

            
            # print(f"Class inheritance chain for {(class_name, first_class_id)}:\n{inherited_chain}")
            # print(f"Found Classe: {final_class['name']}")
            # print(f"Found Method: {final_method['name']}")
        return inherited, final_class, final_method

    def _find_inheritance_chain(self, current_classes, current_chain, max_depth, method_name):
        if len(current_classes) > 1:
            pass
            # print(f"Multiple classes found: Method {method_name}")
            # for _, class_node in current_classes.iterrows():
            #     print(f"Class ID: {class_node['id:int']}, Class Name: {class_node['name']}")
        for _, class_node in current_classes.iterrows():
            if len(current_chain) >= max_depth:
                continue
            # Check for circular inheritance
            if class_node['id:int'] in [cid for cid, _ in current_chain]:
                continue
            new_chain = current_chain + [(class_node['id:int'], class_node['name'])]
            # Check if the current class has the target method
            methods = self.nodes_df[
                (self.nodes_df['type'] == 'AST_METHOD') &
                (self.nodes_df['name'] == method_name) &
                (self.nodes_df['classname'] == class_node['name'])
            ]
            # If the method is found or the current class is a built-in class, return the current chain
            if not methods.empty or class_node['name'] in self.php_internal_classes:
                return new_chain
            # Get parent class
            parent_classes = self._get_parent_classes(class_node)
            if not parent_classes.empty:
                result = self._find_inheritance_chain(parent_classes, new_chain, max_depth, method_name)
                if result:
                    return result
        return None

    def _get_parent_classes(self, class_node):
        # Get parent class name
        child_rels = self.rels_df[self.rels_df['start'] == class_node['id:int']][:-1]
        child_nodes = self.nodes_df[self.nodes_df['id:int'].isin(child_rels['end'])]
        parent_class_names = []
        for _, child_node in child_nodes.iterrows():
            if child_node['type'] == 'AST_NAME_LIST':
                child_child_rels = self.rels_df[self.rels_df['start'] == child_node['id:int']]
                child_child_nodes = self.nodes_df[self.nodes_df['id:int'].isin(child_child_rels['end'])]
                for _, child_child_node in child_child_nodes.iterrows():
                    if child_child_node['type'] == 'AST_NAME':
                        name_rels = self.rels_df[self.rels_df['start'] == child_child_node['id:int']]
                        name_nodes = self.nodes_df[self.nodes_df['id:int'].isin(name_rels['end'])]
                        if name_nodes.empty:
                            continue
                        name_node = name_nodes.iloc[0]
                        if name_node['type'] == 'string':
                            parent_class_names.append(name_node['code'])
            elif child_node['type'] == 'AST_NAME':
                name_rels = self.rels_df[self.rels_df['start'] == child_node['id:int']]
                name_nodes = self.nodes_df[self.nodes_df['id:int'].isin(name_rels['end'])]
                if name_nodes.empty:
                    continue
                name_node = name_nodes.iloc[0]
                if name_node['type'] == 'string':
                    parent_class_names.append(name_node['code'])
                    
        if not parent_class_names:
            return pd.DataFrame()
        
        # Split namespace and class name
        parent_classes = pd.DataFrame()
        for parent_class_name in parent_class_names:
            parent_namespace, parent_name = self._split_namespace_and_identifier(parent_class_name)
            # Find parent class
            if parent_class_name in self.php_internal_classes:
                # print(f"Parent class is built-in: {parent_class_name}")
                parent_classes = pd.concat([
                    parent_classes,
                    pd.DataFrame([{
                        'id:int': -1,
                        'name': parent_class_name,
                        'namespace': parent_namespace,
                        'type': 'AST_CLASS'
                    }])
                ])
            parent_classes = pd.concat([
                parent_classes,
                self.nodes_df[
                    (self.nodes_df['type'] == 'AST_CLASS') &
                    (self.nodes_df['name'] == parent_name) &
                    (self.nodes_df['namespace'] == parent_namespace if parent_namespace else True)
                ]
            ])
        return parent_classes

    def _find_func_decl_by_name(self, func_name):

        name_space, func_name = self._split_namespace_and_identifier(func_name)
        # print(f"Namespace: {name_space}, Function name: {func_name}") if name_space else None

        funcs = self.nodes_df[
            (self.nodes_df['type'].isin(['AST_FUNC_DECL'])) &
            (self.nodes_df['name'] == func_name) &
            (self.nodes_df['namespace'] == name_space if name_space else True)
        ]

        if funcs.empty:
            print(f"Function not found: {func_name}")

        return funcs

    def _clean_php_lines(self, lines, file_name):
        # return lines # [Uncomment this line to keep comments]
        content = '\n'.join(lines)
        try:
            
            process = subprocess.run(
                ['php', 'clean.php'],
                input=content.encode('utf-8'),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            
            result = json.loads(process.stdout)
            if result['error'] != '':
                print(f"PHP Cleaner Errors for {file_name}: \n{result['error']}")
            
            cleaned_code = result['code']

            return cleaned_code.splitlines()
        
        except Exception as e:
            error_msg = e.stderr.decode('utf-8', errors='ignore') if hasattr(e, 'stderr') else str(e)
            print(f"PHP Cleaner Errors: {error_msg}")
            # Return original lines instead of empty list
            print(f"Returning original lines for {file_name} due to cleaning errors")
            return lines

    def _add_lines(self, lines, file_name='', start_lineno=None, end_lineno=None, include_tag=False, main_tag=False):
        
        if not lines:
            return

        if start_lineno is None and end_lineno is None:
            cleaned_lines = self._clean_php_lines(lines, file_name)
        else:
            start_lineno = start_lineno if start_lineno is not None else 0
            end_lineno = end_lineno if end_lineno is not None else len(lines)
            ori_lines = lines[start_lineno:end_lineno]
            ori_lines = ['<?php\n'] + ori_lines + ['?>\n']
            cleaned_lines = self._clean_php_lines(ori_lines, file_name)

        self.files_and_lines[file_name] = []
        for line in cleaned_lines:
            line = line.rstrip()
            # if not line:
            #     continue
            
            # Add the processed line to the assembled code
            if include_tag:
                self.files_and_lines[file_name].append(line)
            if main_tag:
                self.assembled_code_lines.append(line)

    def _finalize_code(self, code_lines):
        
        return '\n'.join(code_lines).replace('?string', '').replace('(): ?', '')

    def _categorize_and_record_called_functions(self, item_type, identifier):
        
        if item_type == 'method':
            if '::' in identifier:
                class_name, method_name = identifier.split('::')
                if class_name in self.executed_user_funcs['classes']:
                    self.executed_user_funcs['classes'][class_name]['static_methods'].add(method_name)
                else:
                    self.executed_user_funcs['classes'][class_name] = {'static_methods': {method_name}, 'instance_methods': set()}
            else:
                class_name, method_name = identifier.split('->')
                if class_name in self.executed_user_funcs['classes']:
                    self.executed_user_funcs['classes'][class_name]['instance_methods'].add(method_name)
                else:
                    self.executed_user_funcs['classes'][class_name] = {'static_methods': set(), 'instance_methods': {method_name}}
        else:
            self.executed_user_funcs['functions'].add(identifier)
    
    def _categorize_and_record_registered_functions(self, item_type, file_path, identifier):
        
        if item_type == 'method':
            if '::' in identifier:
                class_name, method_name = identifier.split('::')
                if class_name in self.files_and_class_method_funcs_within[file_path]['classes']:
                    self.files_and_class_method_funcs_within[file_path]['classes'][class_name]['static_methods'].add(method_name)
                else:
                    self.files_and_class_method_funcs_within[file_path]['classes'][class_name] = {'static_methods': {method_name}, 'instance_methods': set()}
            else:
                class_name, method_name = identifier.split('->')
                if class_name in self.files_and_class_method_funcs_within[file_path]['classes']:
                    self.files_and_class_method_funcs_within[file_path]['classes'][class_name]['instance_methods'].add(method_name)
                else:
                    self.files_and_class_method_funcs_within[file_path]['classes'][class_name] = {'static_methods': set(), 'instance_methods': {method_name}}
        elif item_type == 'function':
            self.files_and_class_method_funcs_within[file_path]['functions'].add(identifier)

    def _find_start_end_lines(self, decl_node):
        
        start_line = decl_node['lineno:int']
        end_line = decl_node['endlineno:int']
        return int(start_line), int(end_line)

    def _get_code_line_content_by_filename_and_lineno(self, filename, lineno):
        
        file_path = os.path.join(self.app_parent_dir, filename)
        lineno = int(lineno)
        
        # Use cache to avoid repeated reads
        if filename not in self._file_cache:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self._file_cache[filename] = f.readlines()
            except FileNotFoundError:
                raise ValueError(f"File {filename} not found in {self.app_parent_dir}")
        
        lines = self._file_cache[filename]
        
        if lineno < 1 or lineno > len(lines):
            raise ValueError(f"Line number {lineno} out of range for {filename}")
        
        return lines[lineno-1].rstrip()

    def _replace_dynamic_include_to_static(self):
        
        # Use a dictionary to record file modifications and reduce list operations
        file_modifications = defaultdict(list)
        
        # Pre-generate all replacement content
        for info_group, included_files in self.include_stat_locations_and_namelist.items():
            filename, lineno, func_call = info_group
            try:
                original = self._get_code_line_content_by_filename_and_lineno(filename, lineno)
                # Use generator expressions to optimize string concatenation
                new_content = original.rstrip() + '\n' + '\n'.join(
                    f'{func_call} "{file.replace("/", "+")}";  /* [Artificial] */' 
                    for file in included_files
                )
                file_modifications[filename].append( (lineno, original, new_content) )
            except ValueError as e:
                print(f"Skipping replacement due to error: {e}")
                continue

        # Batch process file modifications
        for filename, modifications in file_modifications.items():
            # Initialize file content storage structure (using a copy from the cache)
            if filename not in self.files_and_lines:
                self.files_and_lines[filename] = self._file_cache[filename].copy()
            
            # Sort in reverse to avoid line number changes affecting the process
            for lineno, original, new in sorted(modifications, reverse=True):
                lineno = int(lineno)
                idx = lineno - 1
                if idx >= len(self.files_and_lines[filename]):
                    continue
                
                # Exactly match the current line content
                current_line = self.files_and_lines[filename][idx].rstrip()
                if original in current_line:
                    # Directly replace the specified line content
                    pass
                    self.files_and_lines[filename][idx] = f"{new}\n"
                    # print(f"Updated line {lineno} in {filename}: \n{new}\n-----")
                else:
                    print(f"Line {lineno} content mismatch in {filename}. Expected '{original}', found '{current_line}'")
    
    def _replace_dynamic_to_static(self):
        
        # Define regex and processing configurations for each type
        handlers = [
            {   # Handle dynamic class instantiation (new $var(...))
                "node_types": ["AST_NEW"],
                "child_check": lambda nodes: nodes[0].type == "AST_VAR",
                "pattern": re.compile(
                    r'(.*?\bnew\s*\$)(\w+)(\s*\(.*?\)\s*;)', 
                    re.DOTALL
                ),
                "resolve_key": lambda fcall: fcall.split('->__construct')[0]
            },
            {   # Handle dynamic method calls ($var->method() or $var::method())
                "node_types": ["AST_STATIC_CALL", "AST_METHOD_CALL"],
                "child_check": lambda nodes: nodes[1].type == "AST_VAR",  # The second child node is the method name variable
                "pattern": re.compile(
                    r'(.*?)(\$?(\w+))(::|->)(\$\w+)\s*\((.*?)\)\s*;',
                    re.DOTALL | re.VERBOSE
                ),
                "resolve_key": lambda fcall: fcall
            },
            {   # Handle dynamic function calls ($func(...))
                "node_types": ["AST_CALL"],
                "child_check": lambda nodes: nodes[0].type == "AST_VAR",
                "pattern": re.compile(
                    r'(.*?)(\$(\w+))\s*\((.*?)\)\s*;',
                    re.DOTALL | re.VERBOSE
                ),
                "resolve_key": lambda fcall: fcall
            }
        ]

        for file_name, lines in self.files_and_lines.items():
            curr_file_node = self._find_toplevel_file_node_by_filename(file_name)
            if curr_file_node is None:
                print(f"File node not found for {file_name}")
                continue

            next_file_node = self._find_next_toplevel_node(curr_file_node['id:int'])
            next_file_id = next_file_node['id:int'] if next_file_node is not None else None

            # Get all relevant nodes at once
            all_nodes = pd.DataFrame()
            for handler in handlers:
                for node_type in handler["node_types"]:
                    nodes = self._map_specific_node_type_in_current_file(
                        node_type, 
                        curr_file_node['id:int'], 
                        next_file_id
                    )
                    all_nodes = pd.concat([all_nodes, nodes])

            modifications = []
            for _, node in all_nodes.iterrows():
                lineno = int(node['lineno:int'])
                if lineno <= 0 or lineno > len(lines):
                    continue

                # Select processing logic based on node type
                handler = next(
                    (h for h in handlers if node['type'] in h["node_types"]),
                    None
                )
                if not handler:
                    continue

                # Check if child nodes meet requirements
                child_rels = self.rels_df[self.rels_df['start'] == node['id:int']]
                child_nodes = [
                    self.nodes_df[self.nodes_df['id:int'] == rel['end']].iloc[0] 
                    for _, rel in child_rels.iterrows()
                ]
                if not handler["child_check"](child_nodes):
                    continue

                line_content = lines[lineno - 1].rstrip()

                # Parse actual calls from detailed_info
                resolved_names = set()
                if file_name in self.detailed_info:
                    for ln_seq, item_info in self.detailed_info[file_name].items():
                        current_lineno = int(ln_seq.split(', ')[0])
                        if current_lineno == lineno:
                            func_call = item_info.get('func_call', '')
                            key = handler["resolve_key"](func_call)
                            if key:
                                resolved_names.add(key)

                if not resolved_names:
                    continue

                # Regex match
                match = handler["pattern"].search(line_content)
                if not match:
                    continue

                # Generate replacement code based on type
                replacement = line_content
                for name in resolved_names:
                    if node['type'] == "AST_NEW":
                        static_code = match.group(0).replace(f'${match.group(2)}', name)
                    elif node['type'] == "AST_STATIC_CALL":
                        static_code = f"{match.group(1)}{name}({match.group(6)});"
                    elif node['type'] == "AST_METHOD_CALL":
                        static_code = f"{match.group(1)}{match.group(2)}{match.group(4)}{name.split('->')[-1]}({match.group(6)});"
                    else:  # AST_CALL
                        static_code = f"{match.group(1)}{name}({match.group(4)});"
                    
                    if 'return' not in line_content:
                        replacement += f"\n{static_code}  /* [Artificial] */"
                    else:
                        replacement = f"{static_code}  /* [Artificial] */\n{replacement}"

                modifications.append((lineno - 1, replacement))

            # Apply modifications uniformly
            for idx, replacement in sorted(modifications, reverse=True, key=lambda x: x[0]):
                lines[idx] = replacement

            # Output log
            if modifications:
                pass
                # print('-----')
                print(f"Processed {len(modifications)} dynamic calls in {file_name}:")
                # for idx, _ in modifications:
                #     print(f"Updated line {idx + 1}: \n{lines[idx]}")

    def assemble_execution_flow(self):
        
        main_info = self.main_info
        main_filename = ''
        for main_sequence, main_item_info in main_info.items():
            file_path = main_item_info["file_path"]
            main_filename = file_path
            self._register_file_definitions(file_path)
            with open(file_path, 'r', encoding='utf-8') as f:
                self.files_and_lines[file_path] = f.readlines()
            # self._add_lines(cleaned_content, file_path, include_tag=True, main_tag=True)

        class_and_method_to_be_added = defaultdict(set) # {class_id, class_name}: [{method_id, method_name}, ...]
        file_and_lines_to_be_added = defaultdict(set) # file: [{start_line, end_line}, ...]
        for entry in self.execution_order:
            filename = entry["filename"]
            lineno = entry["lineno"]
            sequence = entry["sequence"]
            item_info = self.detailed_info.get(filename, {}).get(f"{lineno}, {sequence}")

            if not item_info:
                print("No detailed info found")
                continue

            if item_info.get("func_call") in ["include", "require", "require_once", "include_once"]:
                included_file = item_info.get("included_file")
                if not included_file:
                    print("Included file path missing")
                    continue
                self.include_stat_locations_and_namelist[(filename, lineno, item_info.get("func_call"))].add(included_file)
                if not self._check_and_add_item('file', included_file):
                    continue
                try:
                    self._register_file_definitions(included_file)
                    with open(included_file, 'r', encoding='utf-8') as f:
                        self.files_and_lines[included_file] = f.readlines()
                except FileNotFoundError:
                    print(f"File {included_file} missing")
                    continue
                
                # self._add_lines(cleaned_content, included_file, include_tag=True)
            else:
                if item_info.get("is_built_in"):
                    # print(f"Skipping built-in: {item_info.get('func_call')}")
                    continue
                
                full_name = item_info.get("func_call")
                # print(f"Executed user function: {func_name}")
                # handle class and method
                if '::' in full_name or '->' in full_name:
                    if not self._check_and_add_item('method', full_name):
                        # print(f"{full_name} was processed. Skipping.")
                        self._categorize_and_record_called_functions('method', full_name)
                        continue
                    inherited, class_node, method_node = self._find_class_method_by_names(full_name, filename) # get inheritance chain
                    if class_node is not None and method_node is not None:
                        item_type = 'method'
                        # name_space = self._get_name_space_from_nodes_df(class_node)
                        # print(f"Found method ({method_node['id:int']}, {method_node['name']}) in class ({class_node['id:int']}, {class_node['name']})")
                        # # Add to the list of classes and methods to be added
                        # class_and_method_to_be_added[(name_space, class_node['id:int'], class_node['name'])].add((method_node['id:int'], method_node['name']))
                    else:
                        continue
                # handle function
                else:
                    # TODO not yet see any fun added cases. leave for future
                    if not self._check_and_add_item('function', full_name):
                        # print(f"{full_name} was processed. Skipping.")
                        self._categorize_and_record_called_functions('function', full_name)
                        continue
                    func_decl_nodes = self._find_func_decl_by_name(full_name)
                    if not func_decl_nodes.empty:
                        item_type = 'function'
                        func_decl_node = func_decl_nodes.iloc[0]
                        name_space = self._get_name_space_from_nodes_df(func_decl_node)
                        start_line, end_line = self._find_start_end_lines(func_decl_node)
                        # print(f"Found function {name_space}{func_decl_node['id:int']}, lineno {start_line} to {end_line}")
                    else:
                        continue
                
                # Categorize and record called functions
                self._categorize_and_record_called_functions(item_type, full_name)
                # print(f"Including {item_type} {full_name}")


        self._replace_dynamic_include_to_static()
        self._replace_dynamic_to_static()

        for file_name, lines in self.files_and_lines.items():
            # print(f"Processing file: {file_name}")
            if file_name == main_filename:
                self._add_lines(lines, file_name, include_tag=True, main_tag=True)
            else:
                self._add_lines(lines, file_name, include_tag=True)
        
        self.remove_unexecuted_things()
        self._save_code_files()
        # print line count
        sum_lines = 0
        for file_name, lines in self.files_and_lines.items():
            sum_lines += len(lines)
        print(f"Total lines added: {sum_lines}")
        self._save_entry_script_to_file(self._finalize_code(self.assembled_code_lines), self.out_dir)
        # self._save_entry_script_to_file(self.remove_unexecuted_things(self._finalize_code()), self.out_dir)
        self._save_executed_funcs_to_json(self.out_dir)
        # print(self.executed_user_funcs)
        # print()
        # print(self.files_and_class_method_funcs_within)
        # print()
        # print(self.files_and_classes_on_inheritance_chain)

    def _save_code_files(self):
        if os.path.exists(self.out_dir):
            shutil.rmtree(self.out_dir)
        os.makedirs(self.out_dir, exist_ok=True)
        print(f"Saving code files to {self.out_dir}")
        for file_name, lines in self.files_and_lines.items():
            mod_file_name = file_name.replace('/', '+')
            file_path = os.path.join(self.out_dir, mod_file_name)
            if re.match(r'^\s*$', self._finalize_code(lines)):
                # print(f"Skipping empty file: {file_path}")
                continue
            # print(f"Saving file: {file_path}")
            with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f'<?php\n# The code from {file_name} [START]\n\n')
                    f.write(self._finalize_code(lines))
                    f.write(f'\n\n# The code from {file_name} [END]\n?>\n\n')
        
    def remove_unexecuted_things(self):
        for file_key in list(self.files_and_lines.keys()):
            # Get definitions in this file
            file_defs = self.files_and_class_method_funcs_within.get(file_key, {
                'functions': set(),
                'classes': defaultdict(lambda: {'static_methods': set(), 'instance_methods': set()})
            })
            # print(f"File definitions: {file_defs}")
            
            to_remove = {
                'classes': [],
                'static_methods': defaultdict(list),
                'instance_methods': defaultdict(list),
                'functions': []
            }

            # Process classes
            current_classes = file_defs['classes'].keys()
            executed_classes = self.executed_user_funcs['classes'].keys()
            inheritance_chain_classes = self.files_and_classes_on_inheritance_chain.get(file_key, {'classes': {}})['classes'].keys()
            
            for class_name in current_classes:
                if class_name not in executed_classes and class_name not in inheritance_chain_classes:
                    to_remove['classes'].append(class_name)
                    # print(f"To remove class {class_name} in {file_key}")
                else:
                    pass
                    # print(f"Class {class_name} is executed or inherited in {file_key}")

            # Process static methods
            for class_name, methods in file_defs['classes'].items():
                if class_name in to_remove['classes']:
                    continue  # The class will be deleted, no need to process methods
                
                executed_static = self.executed_user_funcs['classes'].get(class_name, {}).get('static_methods', set())
                inheritance_static = self.files_and_classes_on_inheritance_chain.get(file_key, {'classes': {}})['classes'].get(class_name, {}).get('static_methods', set())
                
                for method in methods['static_methods']:
                    if method not in executed_static and method not in inheritance_static:
                        to_remove['static_methods'][class_name].append(method)
                        # print(f"To remove static method {method} in class {class_name} in {file_key}")
                    else:
                        pass
                        # print(f"Static method {method} in class {class_name} is executed or inherited in {file_key}")

            # Process instance methods
            for class_name, methods in file_defs['classes'].items():
                if class_name in to_remove['classes']:
                    continue
                
                executed_instance = self.executed_user_funcs['classes'].get(class_name, {}).get('instance_methods', set())
                inheritance_instance = self.files_and_classes_on_inheritance_chain.get(file_key, {'classes': {}})['classes'].get(class_name, {}).get('instance_methods', set())
                
                for method in methods['instance_methods']:
                    if method not in executed_instance and method not in inheritance_instance:
                        to_remove['instance_methods'][class_name].append(method)
                        # print(f"To remove instance method {method} in class {class_name} in {file_key}")
                    else:
                        pass
                        # print(f"Instance method {method} in class {class_name} is executed or inherited in {file_key}")

            # Process functions
            for func in file_defs['functions']:
                if func not in self.executed_user_funcs['functions']:
                    to_remove['functions'].append(func)
                    # print(f"To remove function {func} in {file_key}")
                else:
                    pass
                    # print(f"Function {func} is executed in {file_key}")

            # Call PHP script to process the current file
            original_code = '<?php\n\n' + '\n'.join(self.files_and_lines[file_key]) # [Enable this line to remove comments]
            # original_code = '\n'.join(self.files_and_lines[file_key]) # [Enable this line to keep comments]
            input_data = {
                'code': original_code,
                'remove': {
                    'classes': to_remove['classes'],
                    'static_methods': to_remove['static_methods'],
                    'instance_methods': to_remove['instance_methods'],
                    'functions': to_remove['functions']
                }
            }
            
            try:
                process = subprocess.run(
                    ['php', 'remove.php'],
                    input=json.dumps(input_data),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    encoding='utf-8',
                    timeout=30
                )
                
                if process.returncode != 0:
                    print(f"Error processing {file_key}: {process.stderr}")
                    print(f"Keeping original code for {file_key}")
                    # Keep original code instead of skipping
                    self.files_and_lines[file_key] = original_code.splitlines()
                    continue
                
                result = json.loads(process.stdout)
                if 'error' in result and 'code' in result:
                    print(f"PHP Remover Error for {file_key}: {result['error']}")
                    print(f"Using processed code with errors for {file_key}")
                    # Use the processed code even with errors
                    removed_code = result['code'].split('\n')
                    self.files_and_lines[file_key] = removed_code
                elif 'error' in result:
                    print(f"PHP Remover Error for {file_key}: {result['error']}")
                    print(f"Keeping original code for {file_key}")
                    # Keep original code if no processed code available
                    self.files_and_lines[file_key] = original_code.splitlines()
                else:
                    removed_code = result['code'].split('\n')
                    self.files_and_lines[file_key] = removed_code
                # print(f"Processed {file_key}: {len(cleaned_code)} lines after removal\n")
            except Exception as e:
                print(f"Failed to process {file_key}: {e}")
                print(f"Keeping original code for {file_key}")
                # Keep original code instead of skipping
                self.files_and_lines[file_key] = original_code.splitlines()

    def _save_executed_funcs_to_json(self, output_dir):
        output_file = '/tmp/executed_funcs.json'
        serializable_data = {
            'functions': list(self.executed_user_funcs['functions']),
            'classes': {
                class_name: {
                    'static_methods': list(methods['static_methods']),
                    'instance_methods': list(methods['instance_methods'])
                }
                for class_name, methods in self.executed_user_funcs['classes'].items()
            }
        }
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(serializable_data, f, indent=2, ensure_ascii=False)
        print(f"Saved executed user functions to {output_file}")

    def _save_entry_script_to_file(self, code, output_dir, filename='assembled_code.php'):
        
        # output_file = os.path.join(output_dir, filename)
        output_file = '/tmp/assembled_code.php'
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f'<?php\n# The code from {output_file} [START]\n\n')
            f.write(code)
            f.write(f'\n\n# The code from {output_file} [END]\n?>\n\n')

            for file_name, lines in self.files_and_lines.items():
                f.write(f'<?php\n# The code from {file_name} [START]\n\n')
                f.write('\n'.join(lines))
                f.write(f'\n\n# The code from {file_name} [END]\n?>\n\n')
            
        print(f"Saved assembled code (entry script) to {output_file}")

if __name__ == "__main__":
    timer = time.time()
    parser = argparse.ArgumentParser()
    test_dir = "/app/joomla"
    parser.add_argument('-w', '--working_dir', default=test_dir)
    parser.add_argument('-a', '--app_dir', default='/app/')
    parser.add_argument('-o', '--out', default=test_dir + '/assembled')
    parser.add_argument('-j', '--json_dir', default='/tmp/xdebug')
    
    args = parser.parse_args()

    assembler = CodeAssembler()
    assembler.load_data(args.json_dir, args.ori_app_dir)
    assembler.assemble_execution_flow()
    print(f"Total time taken: {time.time() - timer:.2f} seconds")