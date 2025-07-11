"""setup.py file."""

from setuptools import setup, find_packages

__author__ = "Myrenic"

with open("requirements.txt", "r") as fs:
    reqs = [r for r in fs.read().splitlines() if (len(r) > 0 and not r.startswith("#"))]

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="napalm-eos_ssh_no_enable",
    version="0.0.1",
    packages=find_packages(),
    author="Myrenic",
    author_email="Myrenic",
    description="Napalm driver for Arista Switches over SSH without Enable",
    long_description=long_description,
    long_description_content_type="text/markdown",

    classifiers=[
        "Topic :: Utilities",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: POSIX :: Linux",
    ],
    url="https://github.com/Myrenic/napalm-eos_ssh_no_enable/",
    include_package_data=True,
    install_requires=reqs,
)