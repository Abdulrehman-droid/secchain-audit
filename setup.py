from setuptools import setup, find_packages

setup(
    name="secchain-audit",
    version="1.0.0",
    description="Automated Program Analysis & Large-Scale Measurement Framework for Mobile & IoT Supply Chain Security",
    author="Security Research Team",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "click>=8.0.0",
        "pydantic>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "secchain=secchain.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "License :: OSI Approved :: Apache Software License",
    ],
)
