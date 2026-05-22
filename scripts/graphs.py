import networkx as nx
import matplotlib.pyplot as plt
import time
from utils import *
from collections import defaultdict

class Graphs:
    def __init__(self, rels_df, nodes_df, nodes_df_dict, cpg_edges_df, targets):
        self.rels_df = rels_df
        self.nodes_df = nodes_df
        self.nodes_df_dict = nodes_df_dict
        self.cpg_edges_df = cpg_edges_df
        self.targets = targets
        self.ast = nx.DiGraph()
        self.cg = nx.DiGraph()
        self.cfg = nx.DiGraph()
        self.cfg_mod = nx.DiGraph()
        self.icfg = nx.DiGraph()
        self.icfg_mod = nx.DiGraph()
        self.icfg_mod_without_exit = nx.DiGraph()
        self.icfg_distance = nx.DiGraph()
        self.dg = nx.DiGraph()
        self.idg = nx.DiGraph()
        self.idg_data = nx.DiGraph()
        self.icpg = nx.DiGraph()
        self.icpg_mod = nx.DiGraph()
        self.instrumented_callee_nodes = []
        self.next_cfg_nodes = {}
        self.entry_exit_mapping = {}
        self.file_and_included_files = {}
        self.artificial_idg_nodes = set()

    # REWRITE CHECK CALLEES!!
    def _backward_traverse(self, graph, start_node, flag, visited=None):
        if visited is None:
            visited = set()
        if flag or start_node in visited:
            return
        visited.add(start_node)
        
        if start_node in graph.nodes:
            for node in graph.predecessors(start_node):
                self._backward_traverse(graph, node, True, visited)
            if graph == self.icfg and start_node in self.cg.nodes and self.cg.in_degree(start_node) >= 1:
                self.instrumented_callee_nodes.append(start_node)

    def _build_ast(self):
        # print("Building AST...")
        edges_to_add = (
            (row.start, row.end, {'label': 'REL'})
            for row in self.rels_df.itertuples(index=False)
        )
        self.ast.add_edges_from(edges_to_add)

    def _build_cfg(self):
        # print("Building CFG...")
        cfg_df = self.cpg_edges_df[self.cpg_edges_df['type'] == 'FLOWS_TO']
        edges_to_add = []
        for _, row in cfg_df.iterrows():
            node = self.nodes_df_dict.get(row['start'])
            # AST_EXIT should not flow to any node, this is a bug in PHPJoern
            if node['type'] == 'AST_EXIT':
                continue
            # header node should not be added to CFG, either
            if node['type'] == 'AST_CALL':
                name_node = self.nodes_df_dict.get(row['start'] + 2)
                if name_node and name_node['code'] == 'header':
                    continue
            edges_to_add.append((row['start'], row['end'], {'label': 'CFG'}))
        self.cfg.add_edges_from(edges_to_add)
           
    def _adjust_cfg(self):
        self.cfg_mod = self.cfg.copy()
        # print("Adjusting CFG...")
        ast_df = self.rels_df
        entry_nodes = ast_df[ast_df['type'] == 'ENTRY']
        for _, row in entry_nodes.iterrows():
            self.cfg_mod.add_edge(row['start'], row['end'], label='FUNC_ENTRY')
            # print(f"CFG entry edge {row['start']} -> {row['end']} added")
            
    def _build_cg(self):
        # print("Building CG...")
        cg_df = self.cpg_edges_df[self.cpg_edges_df['type'] == 'CALLS']
        edges_to_add = [(row['start'], row['end'], {'label': 'CG'}) for _, row in cg_df.iterrows()]
        self.cg.add_edges_from(edges_to_add)
    
    def _adjust_cg(self):
        # print("Adjusting CG...")

        # Collect all AST_TOPLEVEL nodes that represent TOPLEVEL_FILE
        toplevel_mask = (
            (self.nodes_df['type'] == 'AST_TOPLEVEL') & 
            (self.nodes_df['flags:string_array'] == 'TOPLEVEL_FILE')
        )
        toplevel_nodes = self.nodes_df[toplevel_mask]

        # Build a dictionary for quick lookup by the last part of the file name
        last_part_map = defaultdict(set)
        for row in toplevel_nodes.itertuples(index=False):
            node_id = getattr(row, '_0')  
            node_name = row.name
            # Get the final segment of the path
            last_segment = node_name.split('/')[-1]
            last_part_map[last_segment].add((node_id, node_name))

        # Iterate all top-level nodes again to find AST_INCLUDE_OR_EVAL within them
        for node in toplevel_nodes.iterrows():
            # node is a tuple (index, row), row is a Series
            top_node_id = node[1]['id:int']

            file_include_mask = (
                (self.nodes_df['type'] == 'AST_INCLUDE_OR_EVAL') &
                (self.nodes_df['flags:string_array'] != 'EXEC_REQUIRE') &
                (self.nodes_df['funcid:int'] == top_node_id)
            )
            file_include_nodes = self.nodes_df[file_include_mask]

            # This dict will map "include_node_id" -> "found_php_path"
            include_and_file_nodes = {}

            # BFS each include_node to find .php file references
            for include_node in file_include_nodes.iterrows():
                include_node_id = include_node[1]['id:int']
                magic_dir_path = ''
                file_name_set = set()
                sub_tree = nx.bfs_tree(self.ast, source=include_node_id)

                for node_id in sub_tree.nodes():
                    curr_node = self.nodes_df_dict.get(node_id, None)
                    if curr_node is None:
                        continue

                    # If we find MAGIC_DIR, we set the dir path
                    if curr_node['flags:string_array'] == 'MAGIC_DIR':
                        magic_dir_path = get_file_name_of_node(node_id, self.nodes_df_dict).split('/')[:-1]
                        magic_dir_path = '/'.join(magic_dir_path)

                    # If we found a string ending with '.php', record it (overwriting previous)
                    if (
                        curr_node['type'] == 'string' and 
                        curr_node['code'].endswith('.php')
                    ):
                        file_name_set.add(curr_node['code'])

                for file_name in file_name_set:
                    include_and_file_nodes[include_node_id] = magic_dir_path + file_name

            # For each discovered file_name, link to the corresponding top-level node(s)
            file_include_cg_edges = []
            for include_node_id, file_name in include_and_file_nodes.items():
                last_part = file_name.split('/')[-1]
                # If no top-level node has that same last segment, skip
                if last_part not in last_part_map:
                    continue

                # Check each candidate to see if its full path actually ends with file_name
                candidates = last_part_map[last_part]
                for candidate_id, candidate_name in candidates:
                    # print(f"Checking {file_name} against {candidate_name}")
                    if candidate_name.endswith(file_name):
                        # It's a match => add CG edge
                        file_include_cg_edges.append((include_node_id, candidate_id, {'label': 'CG'}))
                        # print(f"include CG edge {include_node_id} -> {candidate_id} added")

                        # Also record in self.file_and_included_files for subsequent uses
                        current_set = self.file_and_included_files.get(top_node_id, set())
                        current_set.add(candidate_id)
                        self.file_and_included_files[top_node_id] = current_set

            # Finally, add all discovered edges in one go
            self.cg.add_edges_from(file_include_cg_edges)

        # Debug
        # print(f"file_and_included_files {self.file_and_included_files}")

    def _build_icfg(self):
        # print("Building iCFG...")
        edges_to_add = []
        for u, v, data in self.cfg.edges(data=True):
            edges_to_add.append((u, v, {'label': data.get('label', '')}))
        for u, v, data in self.cg.edges(data=True):
            edges_to_add.append((u, v, {'label': data.get('label', '')}))
        self.icfg.add_edges_from(edges_to_add)

    def _adjust_icfg(self):
        self.icfg_mod = self.icfg.copy()
        self.icfg_mod_without_exit = self.icfg.copy()
        self.icfg_distance = self.icfg.copy()
        self.icfg_distance.remove_edges_from(list(self.cg.edges))
        for u, v, data in self.cfg_mod.edges(data=True):
            self.icfg_mod.add_edge(u, v, label=data.get('label', ''))
            self.icfg_mod_without_exit.add_edge(u, v, label=data.get('label', ''))
            self.icfg_distance.add_edge(u, v, label=data.get('label', ''))
        # add AST edges which link from CFG to CG (call site) nodes
        # print("Adjusting iCFG...")

        for u, v, data in self.cg.edges(data=True):
            # store the parrent node's next CFG node, which will be used to link back to the CFG
            # track back to the first node with CFG edges
            u_parent = u
            # we add CFG_ENTRY_TO_CG edge when we meet the first CFG node
            cfg_entry_to_cg_added = False
            while u_parent not in self.cfg.nodes or self.cfg.out_degree(u_parent) < 1:
                # find the type of the edge from u_parent to u, break if it is FILE or DIRECTORY
                break_flag = False
                for _, _, data in self.ast.in_edges(u_parent, data=True):
                    if data.get('label', '') in ['FILE_OF', 'DIRECTORY_OF']:
                        break_flag = True
                        break
                if break_flag:
                    u_parent = None
                    break
                # always has only one predecessor
                try:
                    if u_parent in self.cfg and self.cfg.in_degree(u_parent) >= 1:
                        u_parent = next(self.cfg.predecessors(u_parent))
                    else:
                        u_parent = next(self.ast.predecessors(u_parent))
                    # we add CFG_ENTRY_TO_CG edge when we meet the first CFG node
                    if not cfg_entry_to_cg_added and u_parent in self.cfg.nodes:
                        cfg_entry_to_cg_added = True
                        self.cfg_mod.add_edge(u_parent, u, label='CFG_ENTRY_TO_CG')
                        self.icfg_mod.add_edge(u_parent, u, label='CFG_ENTRY_TO_CG')
                        self.icfg_mod_without_exit.add_edge(u_parent, u, label='CFG_ENTRY_TO_CG')
                        # print(f"icfg_mod CFG_ENTRY_TO_CG edge {u_parent} -> {u} added")
                except:
                    # print(u_parent, 'has no predecessor (CFG)')
                    u_parent = None
                    break
                
            cfg_edges_from_u = self.cfg.out_edges(u_parent) if u_parent is not None else []
            # find the next CFG node of the parent node
            for _, cfg_node in cfg_edges_from_u:
                if cfg_node in self.cfg.nodes and self.cfg.in_degree(cfg_node) >= 1:
                    self.next_cfg_nodes[u] = cfg_node
                    break
                    
        # link back from CG exit node to CFG
        # v + 2 is the exit node
        for u, v, data in self.cg.edges(data=True):
            # TMP
            if u not in self.next_cfg_nodes.keys():
                print(u, 'not in next_cfg_nodes.keys()')
                continue
            self.icfg_mod.add_edge(v + 2, self.next_cfg_nodes[u], label='CG_EXIT_TO_CFG')
            self.icfg_distance.add_edge(v + 2, self.next_cfg_nodes[u], label='CG_EXIT_TO_CFG')
            # print(f"CG_EXIT_TO_CFG edge {v + 2} -> {self.next_cfg_nodes[u]} added")
            # key is the call site, value is the next CFG node after the exit node
            self.entry_exit_mapping[(u, v)] = self.next_cfg_nodes[u]
        
        # print(self.entry_exit_mapping)

    def _add_cg_for_icfg_distance(self):
        # print("Adding CG edges for iCFG distance...")

        # Collect valid targets that are actually in iCFG distance graph
        targets_in_icfg_distance = [t for t in self.targets if t in self.icfg_distance.nodes()]

        # Build a reversed graph once, to figure out which nodes can reach any target
        icfg_without_cg_reversed = self.icfg_distance.reverse(copy=False)
        icfg_with_cg_reversed = self.icfg_mod_without_exit.reverse(copy=False)

        # This set will contain all nodes that can reach at least one target (in the forward direction).
        all_nodes_can_reach_any_target_without_cg = set()
        all_nodes_can_reach_any_target_with_cg = set()

        # For each target in the reversed graph, do BFS/DFS to gather nodes that can reach this target.
        for tgt in targets_in_icfg_distance:
            if tgt in icfg_without_cg_reversed:
                sub_tree = nx.bfs_tree(icfg_without_cg_reversed, tgt)
                all_nodes_can_reach_any_target_without_cg.update(sub_tree.nodes())
            if tgt in icfg_with_cg_reversed:
                sub_tree = nx.bfs_tree(icfg_with_cg_reversed, tgt)
                all_nodes_can_reach_any_target_with_cg.update(sub_tree.nodes())

        # We'll keep track of which 'v' values are definitely in callee
        target_in_callee = set()
        for u, v, data in self.cg.edges(data=True):
            # Resolve the next_cfg_node if present
            next_cfg_node = self.entry_exit_mapping.get((u, v), -1)

            # Only do the BFS membership checks if 'v' is not already in target_in_callee
            if v not in target_in_callee:
                target_reachable_next_cfg_node = (
                    next_cfg_node != -1 and 
                    next_cfg_node in all_nodes_can_reach_any_target_without_cg
                )
                target_reachable_callee = (v in all_nodes_can_reach_any_target_with_cg)
                target_reachable_exit = (v + 2 in all_nodes_can_reach_any_target_without_cg)

            # print(f"u: {u}, v: {v}, target_in_callee: {target_in_callee}, target_reachable_next_cfg_node: {target_reachable_next_cfg_node}, target_reachable_callee: {target_reachable_callee}, target_reachable_exit: {target_reachable_exit}")
            if (
                v in target_in_callee or
                target_reachable_next_cfg_node or
                (target_reachable_callee and not target_reachable_exit)
            ):
                # If the target is on the callee body
                if target_reachable_callee and not target_reachable_exit:
                    target_in_callee.add(v)

                # Add CG edge to icfg_distance if not exists
                if not self.icfg_distance.has_edge(u, v):
                    # print(f"Graph changed, CG edge {u} -> {v} added")
                    self.icfg_distance.add_edge(u, v, label='CG')

                    # Find the CFG_ENTRY_TO_CG edge in self.icfg_mod.in_edges(u) and replicate it in icfg_distance
                    for edge in self.icfg_mod.in_edges(u):
                        if self.icfg_mod.edges[edge]['label'] == 'CFG_ENTRY_TO_CG':
                            self.icfg_distance.add_edge(edge[0], edge[1], label='CFG_ENTRY_TO_CG')
                            break

        # Finally, remove the CG_EXIT_TO_CFG edge if the target is in the function body
        for node_id in target_in_callee:
            self.icfg_distance.remove_edges_from(list(self.icfg_distance.out_edges(node_id + 2)))


    def _build_dg_and_idg(self):
        # print("Building DG...")
        dg_df = self.cpg_edges_df[self.cpg_edges_df['type'] == 'REACHES']
        edges_to_add = [(row['start'], row['end'], {'label': row['var']}) for _, row in dg_df.iterrows()]
        self.dg.add_edges_from(edges_to_add)
        # print("Building iDG...")
        self.idg = self.icfg_mod.copy()
        self.idg.add_edges_from(edges_to_add)

    def _adjust_idg(self):
        # The current idg is just an intermediate graph for building idg_data
        # print("Adjusting iDG (CG)...")
        self.idg_data = self.dg.copy()
        targets_in_icfg_distance = [target for target in self.targets if target in self.icfg_distance.nodes()]
        # The logic is to find every CG edge in idg
        # for CG_out, trace backward to a parrent with data flow in edges, then check CG_out's succ AST_ARG_LIST
        # for each AST_VAR in AST_ARG_LIST, match the string name with the data flow in edges, if matched, adjust the in edge to cg_in's AST_PARAM_LIST, the position is the same with AST_ARG_LIST
        for u, v, data in self.cg.edges(data=True):
            # skip include CG edges
            if u not in self.file_and_included_files or v not in self.file_and_included_files[u]:
                if v not in self.icfg_distance.nodes:
                    continue
                target_reachable = any(nx.has_path(self.icfg_distance, v, target) for target in targets_in_icfg_distance)
                if not target_reachable:
                    continue
                # find the parent node with data flow in edges
                u_parent = u
                round = 0
                while u_parent not in self.dg.nodes or self.dg.in_degree(u_parent) < 1:
                    round += 1
                    # find the type of the edge from u_parent to u, break if it is FILE or DIRECTORY
                    break_flag = False
                    for _, _, data in self.ast.in_edges(u_parent, data=True):
                        if data.get('label', '') in ['FILE_OF', 'DIRECTORY_OF']:
                            break_flag = True
                            break
                    if break_flag or round > 5:
                        u_parent = None
                        break
                    try:
                        u_parent = next(self.ast.predecessors(u_parent))
                    except:
                        # print(u_parent, 'has no predecessor (DG), round =', round)
                        u_parent = None
                        break
                if u_parent is None:
                    continue
                # find the AST_ARG_LIST node
                for succ in self.ast.successors(u):
                    # if self.nodes_df.loc[succ]['type'] == 'AST_ARG_LIST':
                    node = self.nodes_df_dict.get(succ)
                    if node['type'] == 'AST_ARG_LIST':
                        arg_list = succ
                        break
                # find all AST_VAR/AST_PROP/AST_DIM nodes in AST_ARG_LIST
                args = []
                for arg in self.ast.successors(arg_list):
                    # if self.nodes_df.loc[arg]['type'] == 'AST_VAR':
                    node = self.nodes_df_dict.get(arg)
                    if node['type'] == 'AST_VAR':
                        value_id = next(self.ast.successors(arg))
                        args.append(value_id)
                    # if self.nodes_df.loc[arg]['type'] == 'AST_PROP':
                    if node['type'] == 'AST_PROP':
                        # object node
                        object_id = next(self.ast.successors(arg))
                        value_id = next(self.ast.successors(object_id))
                        prop_id = list(self.ast.successors(arg))[1]
                        object_name_node = self.nodes_df_dict.get(value_id)
                        prop_node = self.nodes_df_dict.get(prop_id)
                        args.append((value_id, object_name_node['code'], prop_node['code']))
                        # print('prop ', (value_id, object_name_node['code'], prop_node['code']))
                    if node['type'] == 'AST_DIM':
                        # array node
                        array_id = next(self.ast.successors(arg))
                        value_id = next(self.ast.successors(array_id))
                        dim_id = list(self.ast.successors(arg))[1]
                        array_name_node = self.nodes_df_dict.get(value_id)
                        dim_node = self.nodes_df_dict.get(dim_id)
                        args.append([value_id, array_name_node['code'],dim_node['code']])
                        # print('dim ', [value_id, array_name_node['code'], dim_node['code']])
                args.sort(key=lambda x: x if isinstance(x, int) else x[0])
                # print('args', u, v, args)
                # find the AST_PARAM_LIST node
                for succ in self.ast.successors(v):
                    # if self.nodes_df.loc[succ]['type'] == 'AST_PARAM_LIST':
                    succ_node = self.nodes_df_dict.get(succ)
                    if succ_node['type'] == 'AST_PARAM_LIST':
                        param_list = succ
                        break
                # find all AST_VAR nodes in AST_PARAM_LIST
                params = []
                for param in self.ast.successors(param_list):
                    param_node = self.nodes_df_dict.get(param)
                    # if self.nodes_df.loc[param]['type'] == 'AST_PARAM':
                    if param_node['type'] == 'AST_PARAM':
                        # The second node is the param name
                        params.append((param, list(self.ast.successors(param))[1]))
                params.sort()
                # print('params', u, v, params)
                # add new dg edges from args to params
                # AST_ARG_LIST is just used to match dg edge labels
                # we need to add edge from the nodes (i.e., u_parent's preds) to the AST_PARAM nodes
                for edge in self.dg.in_edges(u_parent):
                    for arg, param in zip(args, params):
                        label = self.dg.edges[edge]['label']
                        # if self.nodes_df.loc[arg]['code'] == self.dg.edges[edge]['label']:
                        if isinstance(arg, int): # AST_VAR
                            arg_node = self.nodes_df_dict.get(arg)
                            if arg_node['code'] == self.dg.edges[edge]['label']:
                                self.idg_data.add_edge(edge[0], arg, label=label)
                                self.idg_data.add_edge(arg, param[0], label=label)
                                self.artificial_idg_nodes.add(arg)
                                # print(f"iDG VAR edge {edge[0]} -> {arg} -> {param[0]} added, label {self.dg.edges[edge]['label']}, *round = {round}")
                        elif isinstance(arg, tuple): # AST_PROP
                            if arg[1] == self.dg.edges[edge]['label']:
                                self.idg_data.add_edge(edge[0], arg[0], label=f"{label}.{arg[2]}")
                                self.idg_data.add_edge(arg[0], param[0], label=f"{label}.{arg[2]}")
                                self.artificial_idg_nodes.add(arg[0])
                                # print(f"iDG PROP edge {edge[0]} -> {arg[0]} -> {param[0]} added, label {self.dg.edges[edge]['label']}.{arg[2]}, *round = {round}")
                        elif isinstance(arg, list): # AST_DIM
                            if arg[1] == self.dg.edges[edge]['label']:
                                self.idg_data.add_edge(edge[0], arg[0], label=f"{label}.{arg[2]}")
                                self.idg_data.add_edge(arg[0], param[0], label=f"{label}.{arg[2]}")
                                self.artificial_idg_nodes.add(arg[0])
                                # print(f"iDG DIM edge {edge[0]} -> {arg[0]} -> {param[0]} added, label {self.dg.edges[edge]['label']}, *round = {round}")
                # find all AST_RETURN nodes in func body
                return_mask = (self.nodes_df['type'] == 'AST_RETURN') & (self.nodes_df['funcid:int'] == v)
                return_nodes = self.nodes_df[return_mask]

                for node in return_nodes.iterrows():
                    succ = next(self.ast.successors(node[1]['id:int']))

                    # if it returns anything, we need to add a data flow edge from the return node to the call site's first AST pred that in igd_data
                    succ_node = self.nodes_df_dict.get(succ)
                    if succ_node['type'] != 'NULL':
                        control_flow_predecessor = get_first_control_or_data_flow_predecessor(u, self.icfg_mod, self.ast, for_data_return=True)
                        if control_flow_predecessor is not None:
                            self.idg_data.add_edge(node[1]['id:int'], control_flow_predecessor, label='DATA_RETURN')
                            # print(f"iDG RETURN edge {node[1]['id:int']} -> {control_flow_predecessor} added, label DATA_RETURN")

        # print("Adjusting iDG (global)...")
        # get all AST_TOPLEVEL	TOPLEVEL_FILE nodes
        toplevel_mask = (self.nodes_df['type'] == 'AST_TOPLEVEL') & (self.nodes_df['flags:string_array'] == 'TOPLEVEL_FILE')
        toplevel_nodes = self.nodes_df[toplevel_mask]
        file_and_assign_nodes = {}
        var_obj_dim_nodes_dict = {}
        global_tag_stmtlist_node_and_var_name = {} # key is the AST_STMT_LIST node' id, value is [var name1, var name2, ...]
        # for each toplevel_node, match all nodes with funcid:int == toplevel_node['id:int'] and type == AST_ASSIGN
        for node in toplevel_nodes.iterrows():
            include_chain_file_ids = set()
            visited = set()
            files_to_process = {node[1]['id:int']}
            while files_to_process:
                file_id = files_to_process.pop()
                if file_id in visited:
                    continue
                visited.add(file_id)
                include_chain_file_ids.add(file_id)
                if file_id in self.file_and_included_files.keys():
                    files_to_process.update(self.file_and_included_files[file_id])
            # get all AST_ASSIGN nodes with funcid:int == toplevel_node['id:int']
            # print(f"include_chain_file_ids {include_chain_file_ids}")
            if node[1]['id:int'] in file_and_assign_nodes.keys():
                assign_nodes = file_and_assign_nodes[node[1]['id:int']]
                global_assign_nodes = assign_nodes['global_assign_nodes']
                in_block_assign_nodes = assign_nodes['in_block_assign_nodes']
            else:
                assign_mask = (self.nodes_df['type'] == 'AST_ASSIGN') & (self.nodes_df['funcid:int'].isin(include_chain_file_ids))
                assign_nodes = self.nodes_df[assign_mask]
                if assign_nodes.empty:
                    continue
                global_assign_nodes = {}
                in_block_assign_nodes = {}
                for assign_node in assign_nodes.iterrows():
                    # find the first AST_STMT_LIST node
                    curr_node_id = assign_node[1]['id:int']
                    curr_node = assign_node[1]
                    while curr_node['type'] != 'AST_STMT_LIST':
                        curr_node_id = next(self.ast.predecessors(curr_node_id))
                        curr_node = self.nodes_df_dict.get(curr_node_id)
                    
                    pred_node_id = next(self.ast.predecessors(curr_node_id))
                    # check if the id:int of the pred is the same as toplevel_node['id:int'] (global var)
                    if pred_node_id in include_chain_file_ids:
                        # print(f"assign_node {assign_node[1]['id:int']} is in the toplevel node {node[1]['id:int']}")
                        left_succ = next(self.ast.successors(assign_node[1]['id:int']))
                        left_succ_node = self.nodes_df_dict.get(left_succ)
                        if left_succ_node['type'] == 'AST_VAR':
                            left_value_node_id = next(self.ast.successors(left_succ))
                            var_name = self.nodes_df_dict.get(left_value_node_id)['code']
                            global_assign_nodes[assign_node[1]['id:int']] = (left_value_node_id, var_name, 'AST_VAR')
                        elif left_succ_node['type'] == 'AST_PROP':
                            succs = list(self.ast.successors(left_succ))
                            obj_node_id = next(self.ast.successors(succs[0]))
                            obj_name = self.nodes_df_dict.get(obj_node_id)['code']
                            prop_name = self.nodes_df_dict.get(succs[1])['code']
                            global_assign_nodes[assign_node[1]['id:int']] = (obj_node_id, obj_name, prop_name, 'AST_PROP')
                        elif left_succ_node['type'] == 'AST_DIM':
                            succs = list(self.ast.successors(left_succ))
                            array_node_id = next(self.ast.successors(succs[0]))
                            array_name = self.nodes_df_dict.get(array_node_id)['code']
                            dim_name = self.nodes_df_dict.get(succs[1])['code']
                            # print(f"array_name {array_name}, dim_name {dim_name}")
                            global_assign_nodes[assign_node[1]['id:int']] = (array_node_id, array_name, dim_name, 'AST_DIM')
                    else: # in block var
                        left_succ = next(self.ast.successors(assign_node[1]['id:int']))
                        left_succ_node = self.nodes_df_dict.get(left_succ)
                        if left_succ_node['type'] == 'AST_VAR':
                            left_value_node_id = next(self.ast.successors(left_succ))
                            var_name = self.nodes_df_dict.get(left_value_node_id)['code']
                            in_block_assign_nodes[assign_node[1]['id:int']] = (left_value_node_id, var_name, 'AST_VAR')
                        elif left_succ_node['type'] == 'AST_PROP':
                            succs = list(self.ast.successors(left_succ))
                            obj_node_id = next(self.ast.successors(succs[0]))
                            obj_name = self.nodes_df_dict.get(obj_node_id)['code']
                            prop_name = self.nodes_df_dict.get(succs[1])['code']
                            in_block_assign_nodes[assign_node[1]['id:int']] = (obj_node_id, obj_name, prop_name, 'AST_PROP')
                        elif left_succ_node['type'] == 'AST_DIM':
                            succs = list(self.ast.successors(left_succ))
                            array_node_id = next(self.ast.successors(succs[0]))
                            array_name = self.nodes_df_dict.get(array_node_id)['code']
                            dim_name = self.nodes_df_dict.get(succs[1])['code']
                            in_block_assign_nodes[assign_node[1]['id:int']] = (array_node_id, array_name, dim_name, 'AST_DIM')
                file_and_assign_nodes[node[1]['id:int']] = {'global_assign_nodes': global_assign_nodes, 'in_block_assign_nodes': in_block_assign_nodes}
            
            var_obj_dim_mask = ((self.nodes_df['type'] == 'AST_VAR') | (self.nodes_df['type'] == 'AST_PROP') | (self.nodes_df['type'] == 'AST_DIM') & (self.nodes_df['funcid:int'].isin(include_chain_file_ids)))
            var_obj_dim_nodes = self.nodes_df[var_obj_dim_mask]
            global_tag_mask = (self.nodes_df['type'] == 'AST_GLOBAL') & (self.nodes_df['funcid:int'].isin(include_chain_file_ids))
            global_tag_nodes = self.nodes_df[global_tag_mask]
            for global_tag_node in global_tag_nodes.iterrows():
                # find the first AST_STMT_LIST node
                curr_node_id = global_tag_node[1]['id:int']
                curr_node = global_tag_node[1]
                while curr_node['type'] != 'AST_STMT_LIST':
                    curr_node_id = next(self.ast.predecessors(curr_node_id))
                    curr_node = self.nodes_df_dict.get(curr_node_id)
                # match AST_GLOBAL tagged AST_VAR/AST_PROP/AST_DIM nodes' name
                succ = next(self.ast.successors(global_tag_node[1]['id:int']))
                succ_node = self.nodes_df_dict.get(succ)
                if succ_node['type'] == 'AST_VAR':
                    value_node_id = next(self.ast.successors(succ))
                    var_name = self.nodes_df_dict.get(value_node_id)['code']
                    global_tag_stmtlist_node_and_var_name[curr_node_id] = global_tag_stmtlist_node_and_var_name.get(curr_node_id, set()).union({var_name})
                elif succ_node['type'] == 'AST_PROP':
                    succs = list(self.ast.successors(succ))
                    obj_node_id = next(self.ast.successors(succs[0]))
                    obj_name = self.nodes_df_dict.get(obj_node_id)['code']
                    prop_name = self.nodes_df_dict.get(succs[1])['code']
                    global_tag_stmtlist_node_and_var_name[curr_node_id] = global_tag_stmtlist_node_and_var_name.get(curr_node_id, set()).union({obj_name})
                elif succ_node['type'] == 'AST_DIM':
                    succs = list(self.ast.successors(succ))
                    array_node_id = next(self.ast.successors(succs[0]))
                    array_name = self.nodes_df_dict.get(array_node_id)['code']
                    dim_name = self.nodes_df_dict.get(succs[1])['code']
                    global_tag_stmtlist_node_and_var_name[curr_node_id] = global_tag_stmtlist_node_and_var_name.get(curr_node_id, set()).union({array_name})
            # build a hash table for quick lookup (type, name) -> list [id:int, ...]
            var_obj_dim_nodes_dict = defaultdict(set)
        for row in var_obj_dim_nodes.itertuples(index=False):
            node_type = row.type
            node_id = getattr(row, '_0') 
            if node_type == 'AST_VAR':
                pred = next(self.ast.predecessors(node_id))
                pred_node = self.nodes_df_dict.get(pred)
                if pred_node['type'] in ['AST_PROP', 'AST_DIM']:
                    continue
                value_node_id = next(self.ast.successors(node_id))
                value_node = self.nodes_df_dict.get(value_node_id)
                var_obj_dim_nodes_dict[(node_type, value_node['code'])].add(value_node_id)
            
            elif node_type == 'AST_PROP':
                succs = list(self.ast.successors(node_id))   
                obj_node_id = next(self.ast.successors(succs[0]))
                obj_node = self.nodes_df_dict.get(obj_node_id)
                obj_name = obj_node['code']
                prop_name = self.nodes_df_dict.get(succs[1])['code']
                var_obj_dim_nodes_dict[(node_type, obj_name, prop_name)].add(obj_node_id)
            
            elif node_type == 'AST_DIM':
                succs = list(self.ast.successors(node_id))
                array_node_id = next(self.ast.successors(succs[0]))
                array_node = self.nodes_df_dict.get(array_node_id)
                array_name = array_node['code']
                dim_name = self.nodes_df_dict.get(succs[1])['code']
                var_obj_dim_nodes_dict[(node_type, array_name, dim_name)].add(array_node_id)
        # print(f"global_tag_stmtlist_node_and_var_name {global_tag_stmtlist_node_and_var_name}")
        # print(f"var_obj_dim_nodes_dict {var_obj_dim_nodes_dict}")
        # print(f"file_and_assign_nodes {file_and_assign_nodes}")
        for file_id, assign_nodes in file_and_assign_nodes.items():
            global_assign_nodes = assign_nodes['global_assign_nodes']
            in_block_assign_nodes = assign_nodes['in_block_assign_nodes']    
            
            for in_block_node_id, in_block_info in in_block_assign_nodes.items():
                # find the first AST_STMT_LIST node
                curr_node_id = in_block_node_id
                curr_node = self.nodes_df_dict.get(curr_node_id)
                while curr_node['type'] != 'AST_STMT_LIST':
                    curr_node_id = next(self.ast.predecessors(curr_node_id))
                    curr_node = self.nodes_df_dict.get(curr_node_id)
                # print(f"curr_stmtlist_node_id {curr_node_id}")
                if curr_node_id in global_tag_stmtlist_node_and_var_name.keys():
                    # print(f"aaa {global_tag_stmtlist_node_and_var_name[curr_node_id]}")
                    pass
                    # link to all other global nodes with the same name
                    if in_block_info[-1] == 'AST_VAR':
                        same_name_node_id = var_obj_dim_nodes_dict.get(('AST_VAR', in_block_info[1]))
                        # print('same_name_node_id', same_name_node_id)
                    elif in_block_info[-1] == 'AST_PROP':
                        same_name_node_id = var_obj_dim_nodes_dict.get(('AST_PROP', in_block_info[1], in_block_info[2]))
                        # print('same_name_node_id', same_name_node_id)
                    elif in_block_info[-1] == 'AST_DIM':
                        same_name_node_id = var_obj_dim_nodes_dict.get(('AST_DIM', in_block_info[1], in_block_info[2]))
                        # print('same_name_node_id', same_name_node_id)
                    if same_name_node_id:
                        for node_id in same_name_node_id:
                            control_flow_predecessor = get_first_control_or_data_flow_predecessor(node_id, self.icfg_mod, self.ast)
                            if in_block_node_id in [node_id, control_flow_predecessor]:
                                continue
                            if control_flow_predecessor in self.icfg_distance.nodes and nx.has_path(self.icfg_distance, in_block_node_id, control_flow_predecessor) and (in_block_node_id, control_flow_predecessor) not in self.idg_data.edges:
                                label = f"{in_block_info[1]}.{in_block_info[2]}" if in_block_info[-1] == 'AST_PROP' else f"{in_block_info[1]}"
                                self.idg_data.add_edge(in_block_node_id, control_flow_predecessor, label=label)
                                # print(f"iDG DATA_GLOBAL (global tagged) edge {in_block_node_id} -> {control_flow_predecessor} added, label {label}")
                                same_name_node = self.nodes_df_dict.get(node_id)

            for global_node_id, global_info in global_assign_nodes.items():
                if global_node_id not in self.icfg_distance.nodes:
                    continue
                global_assign_nodes_copy = global_assign_nodes.copy()
                global_assign_nodes_copy.pop(global_node_id)
                # print(f"node {global_node_id}, info {global_info}")
                if global_info[-1] == 'AST_VAR':
                    same_name_node_id = var_obj_dim_nodes_dict.get(('AST_VAR', global_info[1]))
                    # print('same_name_node_id', same_name_node_id)
                elif global_info[-1] == 'AST_PROP':
                    same_name_node_id = var_obj_dim_nodes_dict.get(('AST_PROP', global_info[1], global_info[2]))
                    # print('same_name_node_id', same_name_node_id)
                elif global_info[-1] == 'AST_DIM':
                    same_name_node_id = var_obj_dim_nodes_dict.get(('AST_DIM', global_info[1], global_info[2]))
                    # print('same_name_node_id', same_name_node_id)
                if same_name_node_id:
                    for node_id in same_name_node_id:
                        control_flow_predecessor = get_first_control_or_data_flow_predecessor(node_id, self.icfg_mod, self.ast)
                        if global_node_id in [node_id, control_flow_predecessor]:
                            continue
                        if nx.has_path(self.icfg_distance, global_node_id, control_flow_predecessor) and (global_node_id, control_flow_predecessor) not in self.idg_data.edges:
                            label = f"{global_info[1]}.{global_info[2]}" if global_info[-1] == 'AST_PROP' else f"{global_info[1]}"
                            self.idg_data.add_edge(global_node_id, control_flow_predecessor, label=label)
                            # print(f"iDG DATA_GLOBAL (same name) edge {global_node_id} -> {control_flow_predecessor} added, label {label}")
                            global_node = self.nodes_df_dict.get(global_node_id)
                            same_name_node = self.nodes_df_dict.get(node_id)
                            if global_node['funcid:int'] != same_name_node['funcid:int']:
                                pass
                                # print(f"global_node {global_node_id}, same_name_node {node_id}, global_node['funcid:int'] {global_node['funcid:int']}, same_name_node['funcid:int'] {same_name_node['funcid:int']}")

    def _build_icpg(self):
        # print("Building iCPG...")
        edges_to_add = []
        for u, v, data in self.ast.edges(data=True):
            edges_to_add.append((u, v, {'label': data.get('label', '')}))
        for u, v, data in self.icfg.edges(data=True):
            edges_to_add.append((u, v, {'label': data.get('label', '')}))
        for u, v, data in self.dg.edges(data=True):
            edges_to_add.append((u, v, {'label': data.get('label', '')}))
    
    def _adjust_icpg(self):
        # print("Adjusting iCPG...")
        for u, v, data in self.icfg_mod.edges(data=True):
            if (u, v) not in self.icpg.edges:
                self.icpg_mod.add_edge(u, v, label=data.get('label', ''))

    def build_all(self):
        self._build_ast()
        self._build_cfg()
        self._build_cg()
        self._adjust_cg()
        self._adjust_cfg()
        self._build_icfg()
        self._adjust_icfg()
        self._add_cg_for_icfg_distance()
        self._build_dg_and_idg()
        self._adjust_idg()
        self._build_icpg()
        self._adjust_icpg()

    def check_callees(self):
        for target in self.targets:
            self._backward_traverse(self.icfg, target, False)
        return self.instrumented_callee_nodes
    
    def draw_and_save(self, graph, name='graph'):
        path = 'WitcherD/working/instrument-info'
        print("Drawing...")
        pos = nx.spring_layout(graph, k=0.5, iterations=50)
        plt.figure(figsize=(9, 9))
        nx.draw(graph, pos, with_labels=True, node_size=500, node_color='lightblue', font_size=8, font_color='black')
        edge_labels = nx.get_edge_attributes(graph, 'label')
        nx.draw_networkx_edge_labels(graph, pos, edge_labels=edge_labels, font_size=6)
        name = '/' + name + '.png'
        plt.savefig(path + name, format="PNG", dpi=300)
        plt.close()
