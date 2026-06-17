"""Setup configuration for DomaScan."""

import sys
import os
import subprocess

if len(sys.argv) == 1:
    print("\n\033[1;36m" + "="*55)
    print("      DomaScan Automated Setup Wizard")
    print("="*55 + "\033[0m\n")
    print("\033[1;34m[*] Starting automated environment setup...\033[0m")
    
    venv_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv")
    
    if not os.path.exists(venv_dir):
        print("\033[1;33m[*] Creating Python virtual environment (venv)...\033[0m")
        try:
            import venv
            venv.create(venv_dir, with_pip=True)
            print("\033[1;32m[+] Virtual environment created successfully.\033[0m")
        except Exception as e:
            print(f"\033[1;31m[-] Failed to create venv: {e}\033[0m")
            sys.exit(1)
    else:
        print("\033[1;32m[+] Virtual environment already exists.\033[0m")

    if os.name == 'nt':
        pip_exe = os.path.join(venv_dir, "Scripts", "pip.exe")
        python_exe = os.path.join(venv_dir, "Scripts", "python.exe")
    else:
        pip_exe = os.path.join(venv_dir, "bin", "pip")
        python_exe = os.path.join(venv_dir, "bin", "python")

    if not os.path.exists(pip_exe):
        print("\033[1;31m[-] Cannot find pip inside virtual environment.\033[0m")
        sys.exit(1)

    print("\033[1;33m[*] Installing required modules...\033[0m")
    try:
        subprocess.check_call([pip_exe, "install", "-r", "requirements.txt"])
        print("\033[1;32m[+] All modules installed successfully.\033[0m")
    except subprocess.CalledProcessError:
        print("\033[1;31m[-] Failed to install requirements.\033[0m")
        sys.exit(1)

    print("\n\033[1;32m" + "="*55)
    print(" 🎉 SETUP COMPLETE! DomaScan is fully ready to use.")
    print("="*55 + "\033[0m\n")
    print("Run the tool easily using the environment python:")
    if os.name == 'nt':
        print(f"\n  \033[1;37mvenv\\Scripts\\python.exe domascan.py --help\033[0m\n")
    else:
        print(f"\n  \033[1;37mvenv/bin/python domascan.py --help\033[0m\n")
    
    sys.exit(0)

try:
    from setuptools import setup, find_packages
except ImportError:
    print("Error: 'setuptools' is not installed. Please run 'pip install setuptools' or 'pip install -r requirements.txt' first.")
    sys.exit(1)

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="domascan",
    version="2.0.0",
    author="Shridhar Kirtane",
    author_email="shridhar3902@example.com",
    description="CLI-based OSINT domain intelligence tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shridhar3902/DomaScan",
    project_urls={
        "Bug Tracker": "https://github.com/shridhar3902/DomaScan/issues",
        "Source Code": "https://github.com/shridhar3902/DomaScan",
    },
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
        "dnspython>=2.3.0",
        "colorama>=0.4.6",
        "python-whois>=0.9.4",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "domascan=modules.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: Utilities",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Environment :: Console",
        "Development Status :: 4 - Beta",
    ],
    license="MIT",
    keywords="osint domain scanner dns whois security reconnaissance",
)
