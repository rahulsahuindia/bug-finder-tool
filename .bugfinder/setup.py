from setuptools import setup, find_packages

setup(
    name="bugfinder",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "PyGithub",
        "tree-sitter",
        "tree-sitter-python",
        "tree-sitter-javascript",
    ],
    entry_points={
        "console_scripts": [
            "bugfinder = bugfinder.main:main",
        ],
    },
)
