from setuptools import setup, find_packages

setup(
    name="swift-security-scanner",
    version="1.0.0",
    description="iOS Swift Security Scanner for OWASP Mobile Top 10 vulnerabilities",
    author="Anil",
    packages=find_packages(),
    install_requires=[
        "click>=8.1.0",
        "colorama>=0.4.6",
        "jinja2>=3.1.0",
        "pyyaml>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "swift-scan=scanner.cli:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)