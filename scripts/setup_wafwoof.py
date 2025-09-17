
import os
import subprocess
import sys
from pathlib import Path

def run_command(cmd, cwd=None):
    try:
        result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def main():
    temp_dir = Path("/tmp/wafw00f_temp")
    temp_dir.mkdir(exist_ok=True)
    
    print("Cloning WAFW00F repository...")
    success, stdout, stderr = run_command(
        "git clone https://github.com/EnableSecurity/wafw00f.git",
        cwd=temp_dir
    )
    
    if not success:
        print(f"Failed to clone WAFW00F: {stderr}")
        return False
    
    wafw00f_dir = temp_dir / "wafw00f"
    plugins_dir = wafw00f_dir / "wafw00f" / "plugins"
    
    if not plugins_dir.exists():
        print("WAFW00F plugins directory not found")
        return False
    
    print("Converting WAFW00F fingerprints...")
    success, stdout, stderr = run_command(
        f"python3 convert_wafwoof.py '{plugins_dir}'",
        cwd="scripts"
    )
    
    if not success:
        print(f"Failed to convert fingerprints: {stderr}")
        return False
    
    print("Cleaning up temporary files...")
    run_command(f"rm -rf '{temp_dir}'")
    
    print("Setup completed successfully!")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)