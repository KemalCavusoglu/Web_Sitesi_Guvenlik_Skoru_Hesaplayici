from setuptools import setup, find_packages

setup(
    name="websiteguvenlikskoru",
    version="0.1.0",
    description="Web Sitesi Güvenlik Skoru hesaplayıcı - MCP ile",
    author="WebGüvenlikSkoru Team",
    author_email="your-email@example.com",
    packages=find_packages(),
    install_requires=[
        "mcp>=1.10.1",
        "requests>=2.31.0",
        "dnspython>=2.4.2",
        "python-dotenv>=1.0.0",
        "sslyze>=5.2.0",
    ],
    entry_points={
        'console_scripts': [
            'websiteguvenlikskoru=run_server:main',
        ],
    },
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
