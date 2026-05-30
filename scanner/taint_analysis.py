import ast
from findings import add_finding


class SecurityVisitor(ast.NodeVisitor):

    def __init__(self, filepath):

        self.filepath = filepath

        self.tainted = set()

    # Detect:
    # x = input()
    def visit_Assign(self, node):

        if isinstance(node.value, ast.Call):

            if isinstance(node.value.func, ast.Name):

                if node.value.func.id == "input":

                    for target in node.targets:

                        if isinstance(target, ast.Name):

                            self.tainted.add(target.id)

        self.generic_visit(node)

    # Detect dangerous function calls
    def visit_Call(self, node):

        # Handle eval()
        if isinstance(node.func, ast.Name):

            if node.func.id == "eval":

                severity = "HIGH"

                issue = "Dangerous eval() usage"

                if node.args:

                    arg = node.args[0]

                    if isinstance(arg, ast.Name):

                        if arg.id in self.tainted:

                            severity = "CRITICAL"

                            issue = "User-controlled input reaches eval()"

                add_finding(
                    severity,
                    "CODE",
                    issue,
                    self.filepath,
                    node.lineno
                )

        # Handle os.system() and subprocess.run()
        elif isinstance(node.func, ast.Attribute):

            # os.system()
            if node.func.attr == "system":

                add_finding(
                    "HIGH",
                    "CODE",
                    "Command Injection via os.system",
                    self.filepath,
                    node.lineno
                )

            # subprocess.run(shell=True)
            if node.func.attr == "run":

                for keyword in node.keywords:

                    if keyword.arg == "shell":

                        if isinstance(keyword.value, ast.Constant):

                            if keyword.value.value is True:

                                add_finding(
                                    "HIGH",
                                    "CODE",
                                    "subprocess.run(shell=True) detected",
                                    self.filepath,
                                    node.lineno
                                )
            if node.func.attr == "loads":
                if isinstance(node.func.value,ast.Name):
                    if node.func.value.id == "pickle":
                        add_finding(
                        "HIGH",
                        "CODE",
                        "Unsafe pickle deserialization detected",
                        self.filepath,
                        node.lineno
                        )
            if node.func.attr == "run":

                for keyword in node.keywords:

                    if keyword.arg == "debug":

                        if isinstance(keyword.value, ast.Constant):

                            if keyword.value.value is True:

                                add_finding(
                                    "MEDIUM",
                                    "CONFIG",
                                    "Flask app running with debug=True",
                                    self.filepath,
                                    node.lineno
                                    )
        self.generic_visit(node)


def scan_python(content, filepath):

    try:

        tree = ast.parse(content)

        visitor = SecurityVisitor(filepath)

        visitor.visit(tree)

    except Exception as e:

        print(f"AST error: {e}")