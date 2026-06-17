"""Setup configuration for DomaScan."""

try:
    from setuptools import setup, find_packages
except ImportError:
    print("Error: 'setuptools' is not installed. Please run 'pip install setuptools' or 'pip install -r requirements.txt' first.")
    import sys
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
