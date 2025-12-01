
import subprocess

# Method 1: Using subprocess.run() (recommended)
# On Windows, use 'type' instead of 'cat'
import platform
if platform.system() == 'Windows':
    result = subprocess.run(['type', 'CURSOR_SECRET.txt'], capture_output=True, text=True, shell=True)
else:
    result = subprocess.run(['cat', 'CURSOR_SECRET.txt'], capture_output=True, text=True)
print("Output:", result.stdout)
print("Error:", result.stderr)
print("Return code:", result.returncode)

