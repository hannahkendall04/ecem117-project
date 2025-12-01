import sys
sys.path.insert(0, '.')
from updated_sanitizer import sanitize_file

try:
    sanitize_file('random.py', 'random_sanitized.py')
    print("Success!")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()

