"""
Code Graph Extractor
Extracts AST, CFG, and DFG from source code for GNN analysis
"""

import ast
import networkx as nx
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class CodeGraphExtractor:
    """Extract code graphs (AST, CFG, DFG) from Python source code"""

    def __init__(self):
        self.node_counter = 0
        self.variable_defs = {}  # Track variable definitions for DFG

    def extract_ast_graph(self, code: str, file_path: str = "") -> nx.DiGraph:
        """
        Extract Abstract Syntax Tree as a directed graph

        Returns:
            NetworkX DiGraph with AST structure
        """
        graph = nx.DiGraph()

        try:
            tree = ast.parse(code)
            self._build_ast_graph(tree, graph, parent_id=None, file_path=file_path)
        except SyntaxError as e:
            logger.warning(f"Syntax error parsing {file_path}: {str(e)}")
            return graph

        return graph

    def _build_ast_graph(
        self,
        node: ast.AST,
        graph: nx.DiGraph,
        parent_id: Optional[str],
        file_path: str
    ) -> str:
        """Recursively build AST graph from AST node"""

        node_id = f"ast_{self.node_counter}"
        self.node_counter += 1

        # Add node with attributes
        node_attrs = {
            'type': 'ast',
            'ast_type': node.__class__.__name__,
            'file_path': file_path,
            'lineno': getattr(node, 'lineno', 0),
            'col_offset': getattr(node, 'col_offset', 0),
        }

        # Add specific attributes for different node types
        if isinstance(node, ast.Name):
            node_attrs['name'] = node.id
        elif isinstance(node, ast.FunctionDef):
            node_attrs['name'] = node.name
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                node_attrs['function'] = node.func.id
            elif isinstance(node.func, ast.Attribute):
                node_attrs['function'] = node.func.attr
        elif isinstance(node, ast.Constant):
            node_attrs['value'] = str(node.value)[:50]  # Limit length

        graph.add_node(node_id, **node_attrs)

        # Add edge from parent
        if parent_id is not None:
            graph.add_edge(parent_id, node_id, edge_type='ast_child')

        # Recursively process children
        for child in ast.iter_child_nodes(node):
            self._build_ast_graph(child, graph, node_id, file_path)

        return node_id

    def extract_cfg_graph(self, code: str, file_path: str = "") -> nx.DiGraph:
        """
        Extract Control Flow Graph

        Simplified CFG that tracks:
        - Function calls
        - Conditionals (if/elif/else)
        - Loops (for/while)
        - Try/except blocks
        - Return statements
        """
        graph = nx.DiGraph()

        try:
            tree = ast.parse(code)
            self._build_cfg_graph(tree, graph, file_path=file_path)
        except SyntaxError as e:
            logger.warning(f"Syntax error parsing {file_path}: {str(e)}")
            return graph

        return graph

    def _build_cfg_graph(
        self,
        node: ast.AST,
        graph: nx.DiGraph,
        prev_node_id: Optional[str] = None,
        file_path: str = ""
    ) -> Optional[str]:
        """Build CFG by connecting control flow nodes"""

        current_node_id = None

        if isinstance(node, ast.FunctionDef):
            # Function entry point
            node_id = f"cfg_func_{self.node_counter}"
            self.node_counter += 1

            graph.add_node(
                node_id,
                type='cfg',
                cfg_type='function',
                name=node.name,
                file_path=file_path,
                lineno=node.lineno
            )

            if prev_node_id:
                graph.add_edge(prev_node_id, node_id, edge_type='cfg_flow')

            # Process function body
            last_node = node_id
            for stmt in node.body:
                last_node = self._build_cfg_graph(stmt, graph, last_node, file_path)

            return last_node

        elif isinstance(node, ast.If):
            # If statement creates branching
            node_id = f"cfg_if_{self.node_counter}"
            self.node_counter += 1

            graph.add_node(
                node_id,
                type='cfg',
                cfg_type='if',
                file_path=file_path,
                lineno=node.lineno
            )

            if prev_node_id:
                graph.add_edge(prev_node_id, node_id, edge_type='cfg_flow')

            # Process if body
            if_last = node_id
            for stmt in node.body:
                if_last = self._build_cfg_graph(stmt, graph, if_last, file_path)

            # Process else body
            else_last = node_id
            for stmt in node.orelse:
                else_last = self._build_cfg_graph(stmt, graph, else_last, file_path)

            # Both branches merge (simplified)
            return if_last

        elif isinstance(node, (ast.For, ast.While)):
            # Loop creates back edge
            node_id = f"cfg_loop_{self.node_counter}"
            self.node_counter += 1

            loop_type = 'for' if isinstance(node, ast.For) else 'while'

            graph.add_node(
                node_id,
                type='cfg',
                cfg_type=loop_type,
                file_path=file_path,
                lineno=node.lineno
            )

            if prev_node_id:
                graph.add_edge(prev_node_id, node_id, edge_type='cfg_flow')

            # Process loop body
            loop_last = node_id
            for stmt in node.body:
                loop_last = self._build_cfg_graph(stmt, graph, loop_last, file_path)

            # Add back edge (loop)
            if loop_last:
                graph.add_edge(loop_last, node_id, edge_type='cfg_back_edge')

            return node_id

        elif isinstance(node, ast.Call):
            # Function call
            node_id = f"cfg_call_{self.node_counter}"
            self.node_counter += 1

            func_name = "unknown"
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            graph.add_node(
                node_id,
                type='cfg',
                cfg_type='call',
                function=func_name,
                file_path=file_path,
                lineno=getattr(node, 'lineno', 0)
            )

            if prev_node_id:
                graph.add_edge(prev_node_id, node_id, edge_type='cfg_flow')

            return node_id

        elif isinstance(node, ast.Return):
            # Return statement
            node_id = f"cfg_return_{self.node_counter}"
            self.node_counter += 1

            graph.add_node(
                node_id,
                type='cfg',
                cfg_type='return',
                file_path=file_path,
                lineno=node.lineno
            )

            if prev_node_id:
                graph.add_edge(prev_node_id, node_id, edge_type='cfg_flow')

            return node_id

        # For other nodes, recursively process children
        for child in ast.iter_child_nodes(node):
            prev_node_id = self._build_cfg_graph(child, graph, prev_node_id, file_path)

        return prev_node_id

    def extract_dfg_graph(self, code: str, file_path: str = "") -> nx.DiGraph:
        """
        Extract Data Flow Graph

        Tracks:
        - Variable definitions
        - Variable uses
        - Data dependencies
        """
        graph = nx.DiGraph()
        self.variable_defs = {}  # Reset for each file

        try:
            tree = ast.parse(code)
            self._build_dfg_graph(tree, graph, file_path=file_path)
        except SyntaxError as e:
            logger.warning(f"Syntax error parsing {file_path}: {str(e)}")
            return graph

        return graph

    def _build_dfg_graph(
        self,
        node: ast.AST,
        graph: nx.DiGraph,
        scope: str = "global",
        file_path: str = ""
    ):
        """Build DFG by tracking variable definitions and uses"""

        if isinstance(node, ast.FunctionDef):
            # New scope for function
            scope = node.name

            # Process function parameters as definitions
            for arg in node.args.args:
                var_name = arg.arg
                node_id = f"dfg_def_{var_name}_{self.node_counter}"
                self.node_counter += 1

                graph.add_node(
                    node_id,
                    type='dfg',
                    dfg_type='definition',
                    variable=var_name,
                    scope=scope,
                    file_path=file_path,
                    lineno=getattr(arg, 'lineno', 0)
                )

                # Track definition
                self.variable_defs[f"{scope}:{var_name}"] = node_id

            # Process function body
            for stmt in node.body:
                self._build_dfg_graph(stmt, graph, scope, file_path)

        elif isinstance(node, ast.Assign):
            # Variable assignment (definition)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    node_id = f"dfg_def_{var_name}_{self.node_counter}"
                    self.node_counter += 1

                    graph.add_node(
                        node_id,
                        type='dfg',
                        dfg_type='definition',
                        variable=var_name,
                        scope=scope,
                        file_path=file_path,
                        lineno=node.lineno
                    )

                    # Track definition
                    self.variable_defs[f"{scope}:{var_name}"] = node_id

            # Process value (right side) - these are uses
            self._track_variable_uses(node.value, graph, scope, file_path)

        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            # Variable use
            var_name = node.id
            use_node_id = f"dfg_use_{var_name}_{self.node_counter}"
            self.node_counter += 1

            graph.add_node(
                use_node_id,
                type='dfg',
                dfg_type='use',
                variable=var_name,
                scope=scope,
                file_path=file_path,
                lineno=getattr(node, 'lineno', 0)
            )

            # Link to definition if exists
            def_key = f"{scope}:{var_name}"
            if def_key in self.variable_defs:
                graph.add_edge(
                    self.variable_defs[def_key],
                    use_node_id,
                    edge_type='dfg_data_flow'
                )
            else:
                # Try global scope
                global_key = f"global:{var_name}"
                if global_key in self.variable_defs:
                    graph.add_edge(
                        self.variable_defs[global_key],
                        use_node_id,
                        edge_type='dfg_data_flow'
                    )

        # Recursively process children
        for child in ast.iter_child_nodes(node):
            self._build_dfg_graph(child, graph, scope, file_path)

    def _track_variable_uses(self, node: ast.AST, graph: nx.DiGraph, scope: str, file_path: str):
        """Track variable uses in expressions"""
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            var_name = node.id
            use_node_id = f"dfg_use_{var_name}_{self.node_counter}"
            self.node_counter += 1

            graph.add_node(
                use_node_id,
                type='dfg',
                dfg_type='use',
                variable=var_name,
                scope=scope,
                file_path=file_path,
                lineno=getattr(node, 'lineno', 0)
            )

            # Link to definition
            def_key = f"{scope}:{var_name}"
            if def_key in self.variable_defs:
                graph.add_edge(
                    self.variable_defs[def_key],
                    use_node_id,
                    edge_type='dfg_data_flow'
                )

        # Recursively check children
        for child in ast.iter_child_nodes(node):
            self._track_variable_uses(child, graph, scope, file_path)

    def create_code_property_graph(self, code: str, file_path: str = "") -> nx.DiGraph:
        """
        Create unified Code Property Graph (CPG)
        Merges AST, CFG, and DFG into single graph

        Returns:
            Unified graph with all three representations
        """
        logger.info(f"Creating CPG for {file_path}")

        # Reset counter for consistent node IDs
        self.node_counter = 0

        # Extract individual graphs
        ast_graph = self.extract_ast_graph(code, file_path)
        cfg_graph = self.extract_cfg_graph(code, file_path)
        dfg_graph = self.extract_dfg_graph(code, file_path)

        # Merge graphs
        cpg = nx.DiGraph()

        # Add all nodes and edges from each graph
        cpg.add_nodes_from(ast_graph.nodes(data=True))
        cpg.add_edges_from(ast_graph.edges(data=True))

        cpg.add_nodes_from(cfg_graph.nodes(data=True))
        cpg.add_edges_from(cfg_graph.edges(data=True))

        cpg.add_nodes_from(dfg_graph.nodes(data=True))
        cpg.add_edges_from(dfg_graph.edges(data=True))

        logger.info(
            f"CPG created: {cpg.number_of_nodes()} nodes, "
            f"{cpg.number_of_edges()} edges"
        )

        return cpg

    def extract_features(self, graph: nx.DiGraph) -> Dict[str, List]:
        """
        Extract numerical features from graph for ML

        Returns:
            Dictionary with feature vectors
        """
        features = {
            'node_features': [],
            'edge_indices': [],
            'edge_types': []
        }

        # Map node IDs to indices
        node_to_idx = {node: idx for idx, node in enumerate(graph.nodes())}

        # Extract node features
        for node_id, node_data in graph.nodes(data=True):
            node_feature = self._encode_node_features(node_data)
            features['node_features'].append(node_feature)

        # Extract edge information
        for source, target, edge_data in graph.edges(data=True):
            source_idx = node_to_idx[source]
            target_idx = node_to_idx[target]

            features['edge_indices'].append([source_idx, target_idx])
            features['edge_types'].append(edge_data.get('edge_type', 'unknown'))

        return features

    def _encode_node_features(self, node_data: Dict) -> List[float]:
        """
        Encode node attributes as numerical feature vector

        Simple encoding for now, can be enhanced with embeddings
        """
        features = [0.0] * 10  # Fixed-size feature vector

        # Encode node type
        if node_data.get('type') == 'ast':
            features[0] = 1.0
        elif node_data.get('type') == 'cfg':
            features[1] = 1.0
        elif node_data.get('type') == 'dfg':
            features[2] = 1.0

        # Encode AST type (simplified)
        ast_type = node_data.get('ast_type', '')
        if 'Call' in ast_type:
            features[3] = 1.0
        elif 'Function' in ast_type:
            features[4] = 1.0
        elif 'If' in ast_type:
            features[5] = 1.0
        elif 'For' in ast_type or 'While' in ast_type:
            features[6] = 1.0

        # Line number (normalized)
        lineno = node_data.get('lineno', 0)
        features[7] = min(lineno / 1000.0, 1.0)  # Normalize

        # Has name attribute
        if 'name' in node_data:
            features[8] = 1.0

        # Is dangerous function
        dangerous_funcs = ['eval', 'exec', 'compile', 'pickle.loads', 'system']
        if node_data.get('function') in dangerous_funcs:
            features[9] = 1.0

        return features
