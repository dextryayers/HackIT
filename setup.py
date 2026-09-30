#!/usr/bin/env python3
"""
HackIt - Security Testing CLI Tool Suite
Setup script for installation
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="hackit",
    version="2.1.0",
    author="Security Researcher",
    description="Comprehensive security testing and penetration testing CLI toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/dextryayers/HackIT",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.1.0",
        "aiohttp>=3.8.0",
        "async-timeout>=4.0.0",
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
        "dnspython>=2.3.0",
        "cryptography>=38.0.0",
        "certifi>=2023.7.22",
        "urllib3>=2.0.0",
        "pysocks>=1.7.1",
        "jinja2>=3.1.2",
        "scapy>=2.5.0",
        "colorama>=0.4.6",
        "fake-useragent>=1.4.0",
        "rich>=13.0.0",
        "tqdm>=4.66.0",
        "shellingham>=1.5.0",
        "tabulate>=0.9.0",
        "psutil>=5.9.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "web": [
            "fastapi>=0.100.0",
            "uvicorn>=0.22.0",
            "httpx>=0.24.0",
            "pydantic>=2.0.0",
            "python-multipart>=0.0.6",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "flake8>=6.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "hackit=hackit.cli:cli",
            "sqli=hackit.sqli:test_sqli",
        ],
    },
)
