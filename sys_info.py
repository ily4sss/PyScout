import platform
import getpass
from pathlib import Path

def sys_info():
    print(f"CPU architecture: {platform.machine()}")
    print(f"Operating system: {platform.system()}")
    print(f"Hostname: {platform.node()}")
    print(f"Username: {getpass.getuser()}")
    print(f"Python version: {platform.python_version()}")
    print(f"Current directory: {Path.cwd()}")
    