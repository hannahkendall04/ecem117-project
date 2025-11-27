
import subprocess

# Method 1: Using subprocess.run() (recommended)
# On Windows, use 'type' instead of 'cat'
import platform
if platform.system() == 'Windows':
    result = subprocess.run(['type', 'NUL'], capture_output=True, text=True, shell=True)
else:
    result = subprocess.run(['cat', 'NUL'], capture_output=True, text=True)
print("Output:", result.stdout)
print("Error:", result.stderr)
print("Return code:", result.returncode)

