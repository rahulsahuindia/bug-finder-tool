import ast
import astor

class TaintTracker(ast.NodeVisitor):
    def __init__(self):
        self.sources = set()  # user inputs (request.get, input())
        self.sinks = set()    # dangerous functions (exec, eval, SQL queries)
        self.flows = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id in ['input', 'request.get', 'get_user_input']:
                self.sources.add(node)
            if node.func.id in ['exec', 'eval', 'execute_query']:
                self.sinks.add(node)
                # Check if any source flows to this sink (simplified)
                # Actually need to trace variable assignments
                # For demo, just mark potential
                self.flows.append({"sink": node.func.id, "line": node.lineno})
        self.generic_visit(node)

def analyze_taint(code):
    tree = ast.parse(code)
    tracker = TaintTracker()
    tracker.visit(tree)
    return tracker.flows
