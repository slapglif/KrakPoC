from setuptools import setup, find_packages

setup(
    name="krack-attack",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'scapy>=2.4.5',
        'rich>=10.0.0',
        'click>=8.0.0',
        'loguru>=0.6.0',
    ],
    entry_points={
        'console_scripts': [
            'krack-attack=krack_cli:main',
        ],
    },
    python_requires='>=3.7',
    author="Your Name",
    author_email="your.email@example.com",
    description="KRACK (Key Reinstallation Attack) Tool",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/krack-attack",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
    ],
) 