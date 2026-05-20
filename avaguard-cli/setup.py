"""Setup script for AVAGuard CLI."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="avaguard",
    version="1.0",
    author="Ahmed Mujtaba",
    description="Azure CIS Benchmark Compliance Checker",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.9",
    install_requires=[
        "azure-identity>=1.15.0",
        "msal>=1.26.0",
        "requests>=2.31.0",
        "click>=8.1.7",
        "colorama>=0.4.6",
        "jinja2>=3.1.3",
        "python-dotenv>=1.0.1",
        "tabulate>=0.9.0",
        "pyyaml>=6.0.1",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.12.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "avaguard=avaguard.cli:main",
        ],
    },
)