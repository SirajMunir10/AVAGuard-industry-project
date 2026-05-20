#!/usr/bin/env python3
"""
AVAGuard Platform - Setup Script

This script installs all dependencies required to run the AVAGuard platform.
Run: pip install -e .
"""

from setuptools import setup, find_packages

# Core dependencies (shared across modules)
CORE_DEPS = [
    "msal>=1.23.0",
    "requests>=2.31.0",
    "python-dateutil>=2.8.2",
]

# CLI dependencies
CLI_DEPS = [
    "click>=8.1.3",
    "colorama>=0.4.6",
    "tabulate>=0.9.0",
]

# Desktop app dependencies
DESKTOP_DEPS = [
    "PyQt6>=6.5.0",
    "pyqt6-qt6>=6.5.0",
]

# Web portal dependencies
WEB_DEPS = [
    "Django>=4.2,<5.0",
    "djangorestframework>=3.14.0",
    "djangorestframework-simplejwt>=5.2.2",
    "django-two-factor-auth>=1.15.5",
    "python-jose[cryptography]>=3.3.0",
    "cryptography>=3.4.8", # Explicitly pulling in cryptography to prevent windows build tools errors on py-jose
    "bcrypt>=4.0.1",
    "whitenoise>=6.5.0",
    "python-dotenv>=1.0.0",
    "django-cors-headers>=4.3.0", 
    "django-otp>=1.3.0",
    "qrcode[pil]>=7.3.1",
    "pyotp>=2.9.0",  # RFC 6238 TOTP for Enterprise MFA
    "pillow>=9.1.0",  # QR code image generation
]

# All dependencies combined
ALL_DEPS = CORE_DEPS + CLI_DEPS + DESKTOP_DEPS + WEB_DEPS

setup(
    name="avaguard",
    version="2.0.0",
    description="Azure AD Compliance Assessment Platform",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="AVAGuard Team",
    author_email="support@avaguard.io",
    url="https://github.com/yourusername/AVAGuard_Project",
    
    packages=find_packages(include=[
        "avaguard_core", "avaguard_core.*",
        "avaguard", "avaguard.*",
    ]),
    
    python_requires=">=3.10",
    
    install_requires=ALL_DEPS,
    
    extras_require={
        "core": CORE_DEPS,
        "cli": CORE_DEPS + CLI_DEPS,
        "desktop": CORE_DEPS + DESKTOP_DEPS,
        "web": WEB_DEPS,
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "flake8>=6.1.0",
        ],
    },
    
    entry_points={
        "console_scripts": [
            "avaguard=avaguard.cli:main",
        ],
    },
    
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    
    keywords="azure, compliance, security, cis-benchmark, audit",
)
