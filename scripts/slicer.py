# lines with distance are recorded in the dist attribute of the calculator class
# lines with divergent distance are in divergent_dist
# so the first step is to keep the func with distance (divergent) or data dependency
# the second step is to keep the BB with distance or data dependency
# the thrid step is to keep the statement with distance or data dependency


from collections import defaultdict
import os
import shutil
import math
import subprocess
from utils import *
from time import sleep
import re
import networkx as nx
import json
import requests
import time
import openai

class Slicer:
    def __init__(self, nodes_df, nodes_df_dict, graphs, calculator, data_flow_analyst, working_dir, app_path):
        self.working_dir = working_dir
        self.app_path = app_path
        self.nodes_df = nodes_df
        self.nodes_df_dict = nodes_df_dict
        self.graphs = graphs
        self.calculator = calculator
        self.data_flow_analyst = data_flow_analyst
        self.skip_BB_nodes = set()
        self.data_dependent_nodes = {} # node_id: data_label
        self.file_line_info = {} # file_name: {(lineno, id): (dist, isDivergent, isDataDependent, data_label)}
        self.file_things_to_add = defaultdict(lambda: {
                'classes': defaultdict(lambda: {'methods': set(), 'properties': set()}), # class_name: {'methods': set(), 'properties': set()}
                'funcs': set(),
                'lines': set()
            }) # file_name: set of things to add
        self.script_and_level = {} # script_name: level
        self.created_files = set()
        self.BB_tree = nx.DiGraph() # stores the structural relationship between BBs

        
        self.app_name = app_path.split('/')[-1] if app_path else 'unknown_app'
        self.vul_type = 'unknown'  # Default value, can be set later

    def sort_dist_with_file_name(self):
        # add dist node
        for k, v in self.calculator.dist.items():
            if v == float('inf'): # do we need to consider inf? It introduces high overhead and maybe useless
                continue
            try:
                lineno = get_lineno_of_node(k, self.nodes_df_dict)
            except:
                continue
            if lineno is None or math.isnan(lineno):
                continue
            file_name = get_file_name_of_node(k, self.nodes_df_dict)
            func_id = get_funcid_of_node(k, self.nodes_df_dict)
            self.file_line_info[file_name] = self.file_line_info.get(file_name, {})
            is_divergent = 1 if k in self.calculator.divergent_node_succs.keys() else 0
            # k is the node id, v is the distance
            self.file_line_info[file_name][(lineno, k)] = {'dist': v, 'isDivergent': is_divergent, 'isDataDependent': 0, 'data_label': '', 'func_id': func_id} # dist, isDivergent, isDataDependent, data_label, func_id
        # add data dependent node
        for k, v in self.data_dependent_nodes.items():
            lineno = get_lineno_of_node(k, self.nodes_df_dict)
            file_name = get_file_name_of_node(k, self.nodes_df_dict)
            func_id = get_funcid_of_node(k, self.nodes_df_dict)
            self.file_line_info[file_name] = self.file_line_info.get(file_name, {})
            if (lineno, k) in self.file_line_info[file_name].keys():
                self.file_line_info[file_name][(lineno, k)]['isDataDependent'] = 1
                self.file_line_info[file_name][(lineno, k)]['data_label'] = v
            else:
                self.file_line_info[file_name][(lineno, k)] = {'dist' : float('inf'), 'isDivergent' : 0, 'isDataDependent' : 1, 'data_label' : v, 'func_id' : func_id} # dist, isDivergent, isDataDependent, data_label, func_id

#######################################

    def debug_bump_dist_to_csv(self):
        with open(os.path.join(self.app_path, 'bump-dist.csv'), 'w') as f:
            f.write("\t".join(['file', 'lineno', 'id', 'dist', 'isDivergent', 'isDataDependent', 'data_label']) + "\n")
            for file_name, node_and_info in self.file_line_info.items():
                for lineno_and_id, detailed_info in sorted(node_and_info.items(), key=lambda x: x[0]):
                    if detailed_info['dist'] == float('inf'):
                        continue
                    if lineno_and_id[1] in self.data_dependent_nodes.keys():
                        detailed_info['isDataDependent'] = 1
                        detailed_info['data_label'] = self.data_dependent_nodes[lineno_and_id[1]]
                    f.write("\t".join([file_name, str(lineno_and_id[0]), str(lineno_and_id[1]), str(detailed_info['dist']), str(detailed_info['isDivergent']), str(detailed_info['isDataDependent']), str(detailed_info['data_label']), str(detailed_info['func_id'])]) + "\n")

    # a DFS visitor for AST structure, return all visited nodes
    def ast_visitor(self, node_id, start_node_lineno, last_top_node=None, visited=None):
        BB_top_labels = ['AST_IF', 'AST_WHILE', 'AST_FOR', 'AST_FOREACH', 'AST_SWITCH', 'AST_TRY']
        BB_skip_labels = ['AST_BREAK', 'AST_EXIT', 'AST_RETURN', 'AST_CATCH_LIST']
        is_start_line_node = False
        is_do_while = False
        node = self.nodes_df_dict.get(node_id)
        if visited is None:
            visited = set()
            if node['type'] == 'AST_DO_WHILE':
                is_do_while = True
        visited.add(node_id)
        if node['type'] in BB_skip_labels:
            self.skip_BB_nodes.add(node_id)
        if get_lineno_of_node(node_id, self.nodes_df_dict) == start_node_lineno:
            is_start_line_node = True
        successors = list(self.graphs.ast.successors(node_id))
        if is_do_while:
            # do not slice the while(); line
            successors.pop(-1) # TODO
        if successors != []:
            for succ in successors:
                succ_node = self.nodes_df_dict.get(succ)
                if succ_node['type'] in BB_top_labels:
                    if succ is not None and last_top_node is not None:
                        self.BB_tree.add_edge(last_top_node, succ)
                    last_top_node = succ
                    continue
                if succ not in visited:
                    self.ast_visitor(succ, start_node_lineno, last_top_node, visited)
        if is_start_line_node:
            visited.remove(node_id)
        return visited if visited != set() else None
            

    def map_data_dependent_nodes(self):
        for edge, node_label in self.data_flow_analyst.data_flow_nodes.items():
            self.data_dependent_nodes[get_first_control_or_data_flow_predecessor(edge[0], self.graphs.icfg_distance, self.graphs.ast)] = node_label

    # wil only be called when performing the first step of slicing
    def backup_original(self, script_path):
        with open(script_path, 'r') as f:
            lines = f.readlines()
            # create a bak file
        with open(script_path + '._0_.php', 'w') as f:
            f.writelines(lines)
        self.created_files.add(script_path + '._0_.php')
        return lines


    def slice(self):
        # preprocessing
        self.map_data_dependent_nodes()
        self.sift_dependent_lines()

        # main logic from here
        # print('\nfile_line_info:', self.file_line_info)

        for file_name, node_and_info in self.file_line_info.items():
            for lineno_and_id, detailed_info in sorted(node_and_info.items(), key=lambda x: x[0]):
                # get the lineno and id
                lineno = lineno_and_id[0]
                node_id = lineno_and_id[1]
                parrent_node = get_node_by_id(detailed_info['func_id'], self.nodes_df_dict)
                parrent_type = parrent_node['type']
                parrent_flags = parrent_node['flags:string_array'].split(',') if not isinstance(parrent_node['flags:string_array'], float) else []
                if parrent_type == 'AST_FUNC_DECL':
                    start_lineno = int(parrent_node['lineno:int'])
                    end_lineno = int(parrent_node['endlineno:int'])
                    self.file_things_to_add[file_name]['funcs'].add((parrent_node['name'], start_lineno, end_lineno))

                elif parrent_type == 'AST_METHOD':
                    class_node_id = get_funcid_of_node(detailed_info['func_id'], self.nodes_df_dict)
                    if class_node_id is None:
                        continue
                    class_node = get_node_by_id(class_node_id, self.nodes_df_dict)
                    if class_node is None:
                        continue
                    class_stmt_list_id = list(self.graphs.ast.successors(class_node_id))[-1]
                    class_stmt_ids = list(self.graphs.ast.successors(class_stmt_list_id))
                    start_lineno = int(parrent_node['lineno:int'])
                    end_lineno = int(parrent_node['endlineno:int'])
                    self.file_things_to_add[file_name]['classes'][class_node['name']]['methods'].add((parrent_node['name'], start_lineno, end_lineno))
                    for class_stmt_id in class_stmt_ids:
                        stmt_node = self.nodes_df_dict.get(class_stmt_id)
                        if stmt_node['type'] == 'AST_PROP_DECL':
                            elem_node_id = list(self.graphs.ast.successors(class_stmt_id))[0]
                            elem_name_id = list(self.graphs.ast.successors(elem_node_id))[0]
                            elem_name_node = self.nodes_df_dict.get(elem_name_id)
                            if elem_name_node['type'] == 'string':
                                self.file_things_to_add[file_name]['classes'][class_node['name']]['properties'].add((elem_name_node['code']))
                        elif stmt_node['type'] == 'AST_METHOD':
                            if stmt_node['name'] in ['__construct', '__destruct', '__call', '__callStatic', '__get', '__set', '__isset', '__unset', '__sleep', '__wakeup', '__toString', '__invoke', '__clone']:
                                start_lineno = int(stmt_node['lineno:int'])
                                end_lineno = int(stmt_node['endlineno:int'])
                                self.file_things_to_add[file_name]['classes'][class_node['name']]['methods'].add((stmt_node['name'], start_lineno, end_lineno))

                elif parrent_type == 'AST_TOPLEVEL':
                    if 'TOPLEVEL_FILE' in parrent_flags:
                        self.file_things_to_add[file_name]['lines'].add((lineno))
                    elif 'TOPLEVEL_CLASS' in parrent_flags:
                        pass
                    
                # visit the ast structure and get all nodes
                visited_nodes = self.ast_visitor(node_id, lineno)
                
                if visited_nodes is None:
                    continue

                # debug
                print(f"Visited nodes for {file_name} at line {lineno}: {visited_nodes}")
            
        serializable_data = {}
        for file_name, file_data in self.file_things_to_add.items():
            serializable_data[file_name] = {
                'classes': {},
                'funcs': list(file_data['funcs']),
                'lines': list(file_data['lines'])
            }
            
            for class_name, class_info in file_data['classes'].items():
                serializable_data[file_name]['classes'][class_name] = {
                    'methods': list(class_info['methods']),
                    'properties': list(class_info['properties'])
                }
        
        # print("\nThings to add: " + json.dumps(serializable_data, ensure_ascii=False, indent=4))

        try:
            print("Generating slices...")
            process = subprocess.run(
                ['php', 'slice.php'],
                input=json.dumps(serializable_data),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding='utf-8',
                timeout=30
            )
            if process.returncode != 0:
                print(f"Error processing slice: {process.stderr}")
            
            result = process.stdout
            
        except Exception as e:
            print(f"Failed to process slice: {e}")
            return None

        # process json result
        slice_dir, result_data = self.save_slices_separate(result)

        # save a full slice file
        full_slice_path = self.save_slices_into_one(slice_dir, result_data)
        # print line count
        with open(full_slice_path) as f:
            line_count = sum(1 for _ in f)
        print(f"Full slice saved to {full_slice_path}, line count: {line_count}")

        
        self.debug_bump_dist_to_csv() 
        return full_slice_path

    def save_slices_into_one(self, slice_dir, result_data):
        full_slice_path = os.path.join(slice_dir, 'full_slice.php')
        with open(full_slice_path, 'w') as f:
            print(f"Saving all slices into {full_slice_path}")
            for file_name, file_data in result_data.items():
                f.write(f"# Code below is from {file_name.split('/')[-1]}\n" + file_data['code'] + f'\n?>\n\n')
        return full_slice_path  # Return the path for patch generation
    
    def save_slices_separate(self, result):
        slice_dir = os.path.join(self.working_dir, 'sliced')
        if os.path.exists(slice_dir):
            shutil.rmtree(slice_dir)  # remove the old sliced dir if exists
        os.makedirs(slice_dir)
        result_data = json.loads(result)
        result_data_copy = result_data.copy()
        for file_name, file_data in result_data_copy.items():
            code_lines = file_data['code'].splitlines()
            final_lines = []
            for i in range(len(code_lines)):
                if '/* [Artificial] */' in code_lines[i].strip() or i+1 < len(code_lines) and '/* [Artificial] */' == code_lines[i+1].strip():
                    print(f'Removing artificial line in {file_name}: {code_lines[i]}')
                    continue
                final_lines.append(code_lines[i])
            result_data[file_name]['code'] = '\n'.join(final_lines)

        for file_name, file_data in result_data.items():
            base_name = os.path.basename(file_name)
            full_path = os.path.join(slice_dir, base_name)
            print(f"Saving slice file: {full_path}")
            with open(full_path, 'w') as f:
                f.write(file_data['code'])
        return slice_dir, result_data
        

    def sift_dependent_lines(self):
        self.sort_dist_with_file_name()
        file_line_info_copy = self.file_line_info.copy()
        for file_k, file_v in file_line_info_copy.items():
            is_not_dependent_file = True
            # remove if neither dist nor data dependency
            for lineno_and_id, detailed_info in list(file_v.items()):
                # if detailed_info['isDivergent'] == 0 and detailed_info['isDataDependent'] == 0:
                if detailed_info['func_id'] is None:
                    del file_v[lineno_and_id]
                if detailed_info['isDivergent'] == 1 or detailed_info['isDataDependent'] == 1:
                    is_not_dependent_file = False
            if file_v == {} or is_not_dependent_file:
                del self.file_line_info[file_k]# debug