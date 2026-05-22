import networkx as nx
from utils import *

class DataFlowAnalyst:
    def __init__(self, dg, icfg, dist, nodes_df, nodes_df_dict, ast):
        self.dg = dg
        self.icfg = icfg
        self.dist = dist
        self.nodes_df = nodes_df
        self.nodes_df_dict = nodes_df_dict
        self.ast = ast
        self.data_flow_nodes = {} # key: (predecessor, successor), value: label
        self.data_flow_origins = {}
        self.dg_edge_labels = nx.get_edge_attributes(dg, 'label')

    def data_flow_backward_traverse(self, start_node, visited=None, current_data_flow_path=[]):
        if visited is None:
            visited = set()
        visited.add(start_node)
        
        if start_node in self.dg.nodes:
            predecessors = list(self.dg.predecessors(start_node))
            for predecessor in predecessors:
                if self.dg_edge_labels.get((predecessor, start_node)) != None:
                    self.data_flow_nodes[(predecessor, start_node)] = str(self.dg_edge_labels[(predecessor, start_node)])
                    # print(f"Data flow edge: {predecessor} -> {start_node}, label: {self.dg_edge_labels[(predecessor, start_node)]}")
                    if current_data_flow_path != []:
                        current_data_flow_path.append(predecessor)
                if predecessor not in visited:
                    if self.dg_edge_labels.get((predecessor, start_node)) in ['CG', 'CFG'] and self.icfg.out_degree(predecessor) >= 2 and self.dist.get(predecessor) == None:
                        continue
                    self.data_flow_backward_traverse(predecessor, visited, current_data_flow_path)
            
            if len(current_data_flow_path) >= 2:
                # print(f"Current data flow path: {current_data_flow_path}")
                data_flow_leaf = current_data_flow_path[0]
                data_flow_root = current_data_flow_path[-1]
                if data_flow_leaf == data_flow_root:
                    return
                if self.data_flow_origins.get(data_flow_leaf) == None:
                    self.data_flow_origins[data_flow_leaf] = [data_flow_root]
                elif data_flow_root not in self.data_flow_origins[data_flow_leaf]:
                    self.data_flow_origins[data_flow_leaf].append(data_flow_root)

    def data_flow_backtrack(self, target_nodes):
        for target in target_nodes:
            if target in self.dg.nodes:
                self.data_flow_backward_traverse(target)
        for instr_node in self.dist.keys():
            if instr_node in self.dg.nodes:
                self.data_flow_backward_traverse(instr_node, current_data_flow_path=[instr_node])
        self.correct_obj_prop()
        # print(f"data_flow nodes: {self.data_flow_nodes}")
        # print(f"data_flow origins: {self.data_flow_origins}")
        return self.data_flow_nodes, self.data_flow_origins
    
    # current DDG cannot identify $obj->$prop. If $obj is on the flow, correct it to specific prop
    # The idea is to first check if there is an AST_PROP out point, then check the in point. 
    # If it is a function call, check all objects in the param list
    def correct_obj_prop(self):
        data_flow_nodes = self.data_flow_nodes.copy()
        for edge, node_label in data_flow_nodes.items():
            # only consider PROP
            if '.' not in node_label:
                continue
            # find control flow predecessors
            # we have two cases, one is the original edges by PHPJoern, the other is the edges added by us in graph builder
            obj, prop = node_label.split('.')
            control_flow_predecessor = get_first_control_or_data_flow_predecessor(edge[0], self.icfg, self.ast)
            preds = list(self.icfg.predecessors(control_flow_predecessor))
            for pred in preds:
                self.correct_obj_prop_backward_traverse(obj, prop, pred, edge[0])

    def correct_obj_prop_backward_traverse(self, obj, prop, start_node, last_node, visited=None):
        if visited is None:
            visited = set()
        visited.add(start_node)

        node = self.nodes_df_dict.get(start_node)
        
        if node['type'] == 'AST_ASSIGN':
            # check left value
            left_succ = next(self.ast.successors(start_node))
            # if self.nodes_df[self.nodes_df['id:int'] == left_succ]['type'] == 'AST_VAR':
            if self.nodes_df_dict.get(left_succ)['type'] == 'AST_VAR':
                left_value_node = next(self.ast.successors(left_succ))
                # check if we operate on the object
                # if self.nodes_df[self.nodes_df['id:int'] == left_value_node]['code'] == obj:
                if self.nodes_df_dict.get(left_value_node)['code'] == obj:
                    self.data_flow_nodes[(start_node, last_node)] = obj
                    # print(f"Corrected data flow edge: {start_node} -> {last_node}, label: {obj}")
            # if self.nodes_df[self.nodes_df['id:int'] == left_succ]['type'] == 'AST_PROP':
            if self.nodes_df_dict.get(left_succ)['type'] == 'AST_PROP':
                # check if we operate on the object->prop
                succs = list(self.ast.successors(left_succ))
                obj_node = next(self.ast.successors(succs[0]))
                curr_obj = self.nodes_df_dict.get(obj_node)['code']
                curr_prop = self.nodes_df_dict.get(succs[1])['code']
                if curr_obj == obj and curr_prop == prop:
                    self.data_flow_nodes[(start_node, last_node)] = f"{obj}.{prop}"
                    # print(f"Corrected data flow edge: {start_node} -> {last_node}, label: {obj}.{prop}")

            preds = list(self.icfg.predecessors(start_node))
            for pred in preds:
                if pred not in visited:
                    self.correct_obj_prop_backward_traverse(obj, prop, pred, start_node, visited)