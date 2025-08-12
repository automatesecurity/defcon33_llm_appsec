import os
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript
import tree_sitter_java as tsjava
import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser
from typing import Dict, List, Set, Tuple
import json
from pathlib import Path


class CallGraphAnalyzer:
    def __init__(self, repo_path: str = "./repo"):
        self.repo_path = repo_path
        self.parsers = self._setup_parsers()
        self.call_graph = {}
        self.function_definitions = {}
        
    def _setup_parsers(self) -> Dict[str, Parser]:
        """Set up tree-sitter parsers for different languages."""
        parsers = {}
        
        # Python
        python_lang = Language(tspython.language())
        python_parser = Parser(python_lang)
        parsers['.py'] = python_parser
        
        # JavaScript/TypeScript
        js_lang = Language(tsjavascript.language())
        js_parser = Parser(js_lang)
        parsers['.js'] = js_parser
        parsers['.ts'] = js_parser
        parsers['.jsx'] = js_parser
        parsers['.tsx'] = js_parser
        
        # Java
        java_lang = Language(tsjava.language())
        java_parser = Parser(java_lang)
        parsers['.java'] = java_parser
        
        # C
        c_lang = Language(tsc.language())
        c_parser = Parser(c_lang)
        parsers['.c'] = c_parser
        parsers['.h'] = c_parser
        
        # C++
        cpp_lang = Language(tscpp.language())
        cpp_parser = Parser(cpp_lang)
        parsers['.cpp'] = cpp_parser
        parsers['.cxx'] = cpp_parser
        parsers['.cc'] = cpp_parser
        parsers['.hpp'] = cpp_parser
        
        return parsers
    
    def _get_file_extension(self, file_path: str) -> str:
        """Get file extension from file path."""
        return Path(file_path).suffix.lower()
    
    def _extract_functions_python(self, tree, source_code: bytes, file_path: str) -> List[Dict]:
        """Extract function definitions and calls from Python code."""
        functions = []
        calls = []
        
        def traverse_tree(node, parent_function=None):
            if node.type == 'function_def':
                func_name_node = node.child_by_field_name('name')
                if func_name_node:
                    func_name = source_code[func_name_node.start_byte:func_name_node.end_byte].decode('utf-8')
                    functions.append({
                        'name': func_name,
                        'file': file_path,
                        'line': node.start_point[0] + 1,
                        'type': 'function_definition'
                    })
                    parent_function = func_name
            
            elif node.type == 'call':
                func_node = node.child_by_field_name('function')
                if func_node:
                    if func_node.type == 'identifier':
                        func_name = source_code[func_node.start_byte:func_node.end_byte].decode('utf-8')
                        calls.append({
                            'caller': parent_function,
                            'callee': func_name,
                            'file': file_path,
                            'line': node.start_point[0] + 1
                        })
                    elif func_node.type == 'attribute':
                        attr_node = func_node.child_by_field_name('attribute')
                        if attr_node:
                            func_name = source_code[attr_node.start_byte:attr_node.end_byte].decode('utf-8')
                            calls.append({
                                'caller': parent_function,
                                'callee': func_name,
                                'file': file_path,
                                'line': node.start_point[0] + 1
                            })
            
            for child in node.children:
                traverse_tree(child, parent_function)
        
        traverse_tree(tree.root_node)
        return functions, calls
    
    def _extract_functions_javascript(self, tree, source_code: bytes, file_path: str) -> List[Dict]:
        """Extract function definitions and calls from JavaScript/TypeScript code."""
        functions = []
        calls = []
        
        def traverse_tree(node, parent_function=None):
            if node.type in ['function_declaration', 'method_definition', 'arrow_function']:
                if node.type == 'function_declaration':
                    name_node = node.child_by_field_name('name')
                elif node.type == 'method_definition':
                    name_node = node.child_by_field_name('name')
                else:  # arrow_function
                    name_node = None
                
                if name_node:
                    func_name = source_code[name_node.start_byte:name_node.end_byte].decode('utf-8')
                    functions.append({
                        'name': func_name,
                        'file': file_path,
                        'line': node.start_point[0] + 1,
                        'type': 'function_definition'
                    })
                    parent_function = func_name
            
            elif node.type == 'call_expression':
                func_node = node.child_by_field_name('function')
                if func_node:
                    if func_node.type == 'identifier':
                        func_name = source_code[func_node.start_byte:func_node.end_byte].decode('utf-8')
                        calls.append({
                            'caller': parent_function,
                            'callee': func_name,
                            'file': file_path,
                            'line': node.start_point[0] + 1
                        })
            
            for child in node.children:
                traverse_tree(child, parent_function)
        
        traverse_tree(tree.root_node)
        return functions, calls
    
    def _extract_functions_java(self, tree, source_code: bytes, file_path: str) -> List[Dict]:
        """Extract function definitions and calls from Java code."""
        functions = []
        calls = []
        
        def traverse_tree(node, parent_function=None):
            if node.type == 'method_declaration':
                name_node = node.child_by_field_name('name')
                if name_node:
                    func_name = source_code[name_node.start_byte:name_node.end_byte].decode('utf-8')
                    functions.append({
                        'name': func_name,
                        'file': file_path,
                        'line': node.start_point[0] + 1,
                        'type': 'method_definition'
                    })
                    parent_function = func_name
            
            elif node.type == 'method_invocation':
                name_node = node.child_by_field_name('name')
                if name_node:
                    func_name = source_code[name_node.start_byte:name_node.end_byte].decode('utf-8')
                    calls.append({
                        'caller': parent_function,
                        'callee': func_name,
                        'file': file_path,
                        'line': node.start_point[0] + 1
                    })
            
            for child in node.children:
                traverse_tree(child, parent_function)
        
        traverse_tree(tree.root_node)
        return functions, calls
    
    def _extract_functions_c_cpp(self, tree, source_code: bytes, file_path: str) -> List[Dict]:
        """Extract function definitions and calls from C/C++ code."""
        functions = []
        calls = []
        
        def traverse_tree(node, parent_function=None):
            if node.type == 'function_definition':
                declarator = node.child_by_field_name('declarator')
                if declarator and declarator.type == 'function_declarator':
                    name_node = declarator.child_by_field_name('declarator')
                    if name_node and name_node.type == 'identifier':
                        func_name = source_code[name_node.start_byte:name_node.end_byte].decode('utf-8')
                        functions.append({
                            'name': func_name,
                            'file': file_path,
                            'line': node.start_point[0] + 1,
                            'type': 'function_definition'
                        })
                        parent_function = func_name
            
            elif node.type == 'call_expression':
                func_node = node.child_by_field_name('function')
                if func_node and func_node.type == 'identifier':
                    func_name = source_code[func_node.start_byte:func_node.end_byte].decode('utf-8')
                    calls.append({
                        'caller': parent_function,
                        'callee': func_name,
                        'file': file_path,
                        'line': node.start_point[0] + 1
                    })
            
            for child in node.children:
                traverse_tree(child, parent_function)
        
        traverse_tree(tree.root_node)
        return functions, calls
    
    def analyze_file(self, file_path: str) -> Tuple[List[Dict], List[Dict]]:
        """Analyze a single file and extract functions and calls."""
        ext = self._get_file_extension(file_path)
        
        if ext not in self.parsers:
            return [], []
        
        try:
            with open(file_path, 'rb') as f:
                source_code = f.read()
            
            parser = self.parsers[ext]
            tree = parser.parse(source_code)
            
            if ext == '.py':
                return self._extract_functions_python(tree, source_code, file_path)
            elif ext in ['.js', '.ts', '.jsx', '.tsx']:
                return self._extract_functions_javascript(tree, source_code, file_path)
            elif ext == '.java':
                return self._extract_functions_java(tree, source_code, file_path)
            elif ext in ['.c', '.h', '.cpp', '.cxx', '.cc', '.hpp']:
                return self._extract_functions_c_cpp(tree, source_code, file_path)
            
        except Exception as e:
            print(f"Error analyzing file {file_path}: {e}")
            return [], []
        
        return [], []
    
    def build_call_graph(self) -> Dict:
        """Build call graph for the entire repository."""
        all_functions = []
        all_calls = []
        
        for root, dirs, files in os.walk(self.repo_path):
            for file in files:
                file_path = os.path.join(root, file)
                functions, calls = self.analyze_file(file_path)
                all_functions.extend(functions)
                all_calls.extend(calls)
        
        # Build function definitions map
        self.function_definitions = {func['name']: func for func in all_functions}
        
        # Build call graph
        call_graph = {}
        for call in all_calls:
            caller = call['caller'] or 'global'
            if caller not in call_graph:
                call_graph[caller] = []
            call_graph[caller].append({
                'callee': call['callee'],
                'file': call['file'],
                'line': call['line']
            })
        
        self.call_graph = call_graph
        return call_graph
    
    def get_call_graph_json(self) -> str:
        """Return call graph as JSON string."""
        if not self.call_graph:
            self.build_call_graph()
        
        return json.dumps({
            'call_graph': self.call_graph,
            'function_definitions': self.function_definitions
        }, indent=2)
    
    def find_callers(self, function_name: str) -> List[str]:
        """Find all functions that call the specified function."""
        callers = []
        for caller, callees in self.call_graph.items():
            for call in callees:
                if call['callee'] == function_name:
                    callers.append(caller)
        return callers
    
    def find_callees(self, function_name: str) -> List[Dict]:
        """Find all functions called by the specified function."""
        return self.call_graph.get(function_name, [])


def create_call_graph_tool(repo_path: str = "./repo"):
    """Create a LangChain Tool for call graph analysis."""
    analyzer = CallGraphAnalyzer(repo_path)
    
    def call_graph_analysis(query: str) -> str:
        """
        Analyze call graph for the repository.
        Query can be:
        - 'build' or 'generate': Build complete call graph
        - 'callers:function_name': Find callers of a function
        - 'callees:function_name': Find callees of a function
        - 'json': Return full call graph as JSON
        """
        try:
            if query.lower() in ['build', 'generate']:
                analyzer.build_call_graph()
                return f"Call graph built successfully. Found {len(analyzer.function_definitions)} functions."
            
            elif query.startswith('callers:'):
                function_name = query.split(':', 1)[1].strip()
                if not analyzer.call_graph:
                    analyzer.build_call_graph()
                callers = analyzer.find_callers(function_name)
                return f"Callers of '{function_name}': {', '.join(callers) if callers else 'None found'}"
            
            elif query.startswith('callees:'):
                function_name = query.split(':', 1)[1].strip()
                if not analyzer.call_graph:
                    analyzer.build_call_graph()
                callees = analyzer.find_callees(function_name)
                if callees:
                    result = f"Functions called by '{function_name}':\n"
                    for call in callees:
                        result += f"- {call['callee']} (at {call['file']}:{call['line']})\n"
                    return result
                else:
                    return f"No functions called by '{function_name}'"
            
            elif query.lower() == 'json':
                return analyzer.get_call_graph_json()
            
            else:
                return ("Invalid query. Use: 'build', 'callers:function_name', "
                       "'callees:function_name', or 'json'")
        
        except Exception as e:
            return f"Error in call graph analysis: {str(e)}"
    
    return call_graph_analysis