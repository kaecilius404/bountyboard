from setuptools import setup, find_packages

setup(
    name="bountyboard",
    version="1.0.0",
    description="Professional-grade automated bug bounty reconnaissance pipeline",
    author="BountyBoard",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "aiohttp>=3.9.0",
        "aiofiles>=23.2.0",
        "dnspython>=2.4.2",
        "click>=8.1.7",
        "pyyaml>=6.0.1",
        "rich>=13.7.0",
        "playwright>=1.40.0",
        "Pillow>=10.1.0",
        "cryptography>=41.0.0",
        "tqdm>=4.66.1",
        "colorama>=0.4.6",
        "tabulate>=0.9.0",
        "jinja2>=3.1.2",
        "aiohttp-socks>=0.8.4",
    ],
    entry_points={
        "console_scripts": [
            "bountyboard=bountyboard.cli:main",
        ],
    },
    package_data={
        "bountyboard": [
            "data/*.txt",
            "data/*.json",
            "templates/*.html",
            "fingerprinting/signatures.json",
        ],
    },
)
