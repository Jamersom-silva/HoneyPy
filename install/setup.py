from setuptools import setup, find_packages
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="honeypy",
    version="1.0.0",
    author="HoneyPy Team",
    author_email="security@example.com",
    description="Sistema de detecção de ataques de brute force",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/honeypy",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "honeypy=src.honeypy:main",
        ],
    },
    package_data={
        "": [
            "config/*.json",
            "install/*.sh",
            "install/systemd/*.service",
        ],
    },
    data_files=[
        ("/etc/honeypy", [
            "config/default_config.json",
            "config/production_config.json",
        ]),
        ("/usr/local/bin", []),
        ("/etc/systemd/system", [
            "install/systemd/honeypy.service",
        ]),
    ],
    include_package_data=True,
    zip_safe=False,
)