import sys
import os
import platform
import re

def sanitize_file(input_path, output_path):
    # Read input Python code
    if os.path.exists(input_path):
        with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    else:
        code = ""

    is_windows = platform.system() == "Windows"

    # Choose safe path
    NULL_FILE = "NUL" if is_windows else "/dev/null"

    # REGEX to replace any cat/type call
    # Matches:
    #   subprocess.run(['cat', 'anything'])
    #   subprocess.run(['type', "anything"], ...)
    sanitized = re.sub(
        r"(subprocess\.run\(\s*\[\s*['\"](cat|type)['\"],\s*['\"][^'\"]+['\"])",
        rf"subprocess.run(['\2', '{NULL_FILE}'",
        code
    )

    # Write sanitized output Python file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(sanitized)

    print(f"Sanitized Python code written to: {output_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python sanitizer.py <input_python_file> <output_python_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    sanitize_file(input_file, output_file)
