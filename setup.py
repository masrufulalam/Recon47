"""
Recon47 - Automated Reconnaissance & Vulnerability Assessment Framework
Author: 0xMasruful
"""

from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))

try:
    with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "Automated Reconnaissance & Vulnerability Assessment Framework"

try:
    with open(os.path.join(here, "requirements.txt"), encoding="utf-8") as f:
        requirements = [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]
except FileNotFoundError:
    requirements = []

setup(
    name="recon47",
    version="1.0.0",
    author="0xMasruful",
    author_email="0xMasruful@proton.me",
    description="Automated Reconnaissance & Vulnerability Assessment Framework for penetration testers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/0xMasruful/recon47",
    project_urls={
        "Bug Tracker": "https://github.com/0xMasruful/recon47/issues",
        "Documentation": "https://github.com/0xMasruful/recon47/blob/main/README.md",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Environment :: Console",
    ],
    # Include ALL modules — they live at top-level, not inside a package
    py_modules=[],
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "recon47=recon47.cli:main",
        ],
    },
    include_package_data=True,
    keywords=[
        "security", "penetration-testing", "reconnaissance",
        "vulnerability-scanner", "bug-bounty", "red-team",
        "recon", "hacking", "cybersecurity",
    ],
    zip_safe=False,
)
