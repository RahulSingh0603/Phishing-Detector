import subprocess
import sys
import os
import time

def start_background():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    venv_python = os.path.join(base_dir, "venv", "Scripts", "pythonw.exe")
    
    if not os.path.exists(venv_python):
        print("Virtual environment not found.")
        sys.exit(1)
        
    print("Starting PhishGuard AI API in background...")
    
    # Use pythonw.exe to run without a console window on Windows
    subprocess.Popen(
        [venv_python, "-m", "uvicorn", "backend.app:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=base_dir,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    )
    
    print("Started.")

if __name__ == "__main__":
    start_background()
