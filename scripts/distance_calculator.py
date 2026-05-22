import networkx as nx
import math
from collections import deque

class DistanceCalculator:
    def __init__(self, targets, graphs):
        self.nodes_df = graphs.nodes_df
        self.nodes_df_dict = graphs.nodes_df_dict
        self.targets = targets
        self.graphs = graphs
        self.icfg = graphs.icfg_distance
        self.entry_exit_mapping = graphs.entry_exit_mapping
        self.dist = {} # node_id: dist
        self.divergent_dist = {}
        self.divergent_node_succs = {} # if a node has only one succ, it is a target.
        self.prob = {}
        self.bb_set = {}
        self.nodes_need_calc = set()
        

    def cal_dist(self, node_id):
        p = self.cal_prob(node_id)
        if math.isclose(p, 0.0, abs_tol=1e-9):
            return float('inf')
        else:
            return round(1 / p, 3)
        

    def cal_prob(self, node_id, visited=[]):
        if self.bb_set[node_id] == 0:
            self.bb_set[node_id] = 1
            if node_id in self.targets:
                self.prob[node_id] = 1.0
            else:
                total_sum = 0.0
                successors = list(self.icfg.successors(node_id))
                for succ in successors:
                    visited.append(node_id)
                    self.prob[succ] = self.cal_prob(succ, visited)
                    total_sum += self.prob[succ]

                num = len(successors)
                if num > 0:
                    self.prob[node_id] = total_sum / num

            self.bb_set[node_id] = 2
        return self.prob[node_id]


    def sift_divergent_dist(self):
        for node_id in self.bb_set.keys():
            if self.icfg.out_degree(node_id) >= 2 or node_id in self.targets:
                # do not instrument the call sites TODO as some call sites has multiple callees with same names, which introduce bugs
                if node_id in self.graphs.cg.nodes() and self.graphs.cg.out_degree(node_id) > 0 and node_id not in self.targets:
                    continue
                has_reachable = False
                has_unreachable = False
                for succ in list(self.icfg.successors(node_id)):
                    # False means unreachable, True means reachable
                    if self.divergent_node_succs.get(node_id) is None:
                        self.divergent_node_succs[node_id] = []
                    if math.isclose(self.prob[succ], 0.0, abs_tol=1e-9):
                        node = self.nodes_df_dict.get(succ)
                        # if not node['type'].isna().values[0]:
                        # if isinstance(node['type'], float):
                        #     print(f"Node {succ} has no type")
                        self.divergent_node_succs[node_id].append((succ, False))
                        has_unreachable = True
                    else:
                        self.divergent_node_succs[node_id].append((succ, True))
                        has_reachable = True
                if node_id in self.targets or has_reachable and has_unreachable and self.dist[node_id] != float('inf'):
                    self.divergent_dist[node_id] = round(self.dist[node_id], 2)
                else:
                    self.divergent_node_succs.pop(node_id)
                # if self.nodes_df[self.nodes_df['id:int'] == node_id]['type'].values[0] in ['CFG_FUNC_EXIT', 'AST_BREAK'] and self.divergent_node_succs.get(node_id):
                if self.nodes_df_dict.get(node_id)['type'] in ['CFG_FUNC_EXIT', 'AST_BREAK'] and self.divergent_node_succs.get(node_id):
                    self.divergent_node_succs.pop(node_id)

    # the distance is not normal because the icfg used to calculate the distance needs to connect the CG back, like the previous version, it must be fine after the modification, that is, adding edges
    def calculate(self):
        print("Calculating block distance...")

        for node_id in self.icfg.nodes():
            if self.icfg.out_degree(node_id) >= 2 or node_id in self.targets:
                self.nodes_need_calc.add(node_id)
                # for succ in list(self.icfg.successors(node_id)):
                #     self.nodes_need_calc.add(succ)
                    
        for node_id in self.icfg.nodes():
            self.bb_set[node_id] = 0
            self.prob[node_id] = 0.0
            self.dist[node_id] = float('inf')

        self.nodes_need_calc = list(self.icfg.nodes()) # TMP DEBUG
        nodes_cal_len = len(self.nodes_need_calc)
    
        round_num = 1
        for node_id in self.nodes_need_calc:
            self.dist[node_id] = self.cal_dist(node_id)
            # Show progress percentage
            # print(f"Calculation progress: {round_num} / {nodes_cal_len}", end="\r")
            round_num += 1
        
        # correct nodes with target reachable succs but no dist
        print("Correcting node dists...")
        dist_changed = True
        runs = 1
        while dist_changed:
            dist_changed = False
            print(f"Dist Correction Run {runs}")
            runs += 1
            wrong_node_queue = deque()
            re_caled_nodes = set()
            for node_id in self.nodes_need_calc:
                if self.dist[node_id] == float('inf'):
                    for succ in list(self.icfg.successors(node_id)):
                        if self.dist[succ] != float('inf') and node_id not in re_caled_nodes:
                            wrong_node_queue.append(node_id)
                            re_caled_nodes.add(node_id)
                            # reset status for re-calculating
                            self.bb_set[node_id] = 0
            while wrong_node_queue:
                node_id = wrong_node_queue.popleft()
                old_dist = self.dist[node_id]
                self.dist[node_id] = self.cal_dist(node_id)
                if not math.isclose(old_dist, self.dist[node_id], abs_tol=1):
                    # print(f"Node {node_id} dist corrected from {old_dist} to {self.dist[node_id]}")
                    dist_changed = True
                # find all preds and add to the queue
                for pred in list(self.icfg.predecessors(node_id)):
                    if pred not in re_caled_nodes:
                        wrong_node_queue.append(pred)
                        re_caled_nodes.add(pred)
                        # reset status for re-calculating
                        self.bb_set[pred] = 0

        self.sift_divergent_dist()

        return self.divergent_dist
