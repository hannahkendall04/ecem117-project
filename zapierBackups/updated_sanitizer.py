import sys
import os
import platform
import re

def sanitize_file(input_path, output_path):
    # Read the Python file
    if os.path.exists(input_path):
        with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    else:
        code = ""

    is_windows = platform.system() == "Windows"
    NULL_FILE = "NUL" if is_windows else "/dev/null"

    # --------------------------------------------------------
    # 1. REMOVE DANGEROUS COMMENT BLOCKS
    # --------------------------------------------------------
    # Remove any triple-quoted comment containing "git clone" and everything after it until closing quotes
    code = re.sub(
        r"'''[^']*git clone[\s\S]*?'''",      # matches the comment containing git clone
        "'''*** REMOVED UNSAFE COMMENT ***'''",
        code,
        flags=re.MULTILINE
    )

    code = re.sub(
        r'"""[^"]*git clone[\s\S]*?"""',      # also support triple double quotes
        '"""*** REMOVED UNSAFE COMMENT ***"""',
        code,
        flags=re.MULTILINE
    )

    # --------------------------------------------------------
    # 2. SANITIZE SUBPROCESS READS (cat/type)
    # --------------------------------------------------------
    code = re.sub(
        r"(subprocess\.run\(\s*\[\s*['\"](cat|type)['\"],\s*['\"][^'\"]+['\"])",
        rf"subprocess.run(['\2', '{NULL_FILE}'",
        code
    )

    # --------------------------------------------------------
    # 3. WRITE OUTPUT FILE
    # --------------------------------------------------------
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(code)

    print(f"Sanitized Python code written to: {output_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python sanitizer.py <input_python_file> <output_python_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    sanitize_file(input_file, output_file)
