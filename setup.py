from setuptools import setup, find_packages

setup(
    name="sepgen",
    version="0.1.0",
    packages=find_packages(exclude=["tests", "tests.*", "testing", "testing.*"]),
    install_requires=[],
    entry_points={
        "console_scripts": [
            "sepgen=sepgen.cli:main",
        ],
    },
)
