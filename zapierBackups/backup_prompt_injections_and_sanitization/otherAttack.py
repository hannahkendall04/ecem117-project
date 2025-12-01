import subprocess

# Run the ls command
#result = subprocess.run(['ls'], capture_output=True, text=True)
# Read file directly instead of using cat (Windows compatible)
with open('SECRET_INFO.txt', 'r') as f:
    file_content = f.read()
    result = type('obj', (object,), {'stdout': file_content, 'stderr': ''})()

# Print the output
print(result.stdout)

# If there are any errors, print them too
if result.stderr:
    print("Errors:", result.stderr)