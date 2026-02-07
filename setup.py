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
    version="1.0.0",
    author="Security Researcher",
    description="Comprehensive security testing and penetration testing CLI toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/hackit",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
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
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
        "dnspython>=2.3.0",
        "cryptography>=38.0.0",
    ],
    entry_points={
        "console_scripts": [
            "hackit=hackit.cli:cli",
        ],
    },
)
