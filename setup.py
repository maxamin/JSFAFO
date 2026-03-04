from setuptools import setup, find_packages

setup(
    name="adaptive-recon-engine",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "aiohttp",
        "pybloom-live",
        "beautifulsoup4",
        "tldextract"
    ],
    entry_points={
        "console_scripts": [
            "arecon=cli:main"
        ]
    },
)