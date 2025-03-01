from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="mail-warden",
    version="0.1.0",
    author="Ryan Stoffel",
    author_email="ryanstoffel62@icloud.com",
    description="A comprehensive email security tool with phishing detection, attachment scanning, and encrypted communications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/RyanStoffel/mail-warden",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "mail-warden=src.main:main",
        ],
    },
    include_package_data=True,
)
