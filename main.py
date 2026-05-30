import os 
from scanner.secrets import scan_secrets 
from scanner.taint_analysis import scan_python
from findings import show_findings,get_severity_counts,findings
import argparse

total_files = 0
python_files = 0
parser = argparse.ArgumentParser(
    description="RepoGuard - Static Application Security Scanner"
)

parser.add_argument(
    "target",
    help="Target directory to scan"
)

args = parser.parse_args()

folder = os.path.abspath(
    os.path.expanduser(args.target)
)

IGNORE_DIRS = {
    ".git",
    "venv",
    "__pycache__",
    "node_modules",
    ".idea",
    ".vscode"
}

SUPPORTED_EXTENSIONS = {
    ".py",
    ".env",
    ".json",
    ".yaml",
    ".yml"
}


for root,dirs,files in os.walk(folder):
    
    dirs[:] = [
        d for d in dirs
        if d not in IGNORE_DIRS
    ]
    for file in files:

        _, ext = os.path.splitext(file)

        if ext not in SUPPORTED_EXTENSIONS:

            continue


        filepath=os.path.join(root,file)
        total_files += 1
        print(f"Reading -: "+filepath)
        try:
            with open(filepath ,'r',encoding="utf-8",errors="ignore") as f:
                content = f.read()
                scan_secrets(content,filepath)
                if ext == ".py":
                    python_files += 1
                    scan_python(content,filepath)
        except Exception as e:
            print(f"could not read file: {e}")

show_findings()
severity_counts = get_severity_counts()

print("\n========== Scan Summary ==========\n")

print(f"Files Scanned   : {total_files}")

print(f"Python Files    : {python_files}")

print(f"Total Findings  : {len(findings)}")

print(f"Critical Issues : {severity_counts['CRITICAL']}")

print(f"High Issues     : {severity_counts['HIGH']}")

print(f"Medium Issues   : {severity_counts['MEDIUM']}")

print(f"Low Issues      : {severity_counts['LOW']}")