from setuptools import setup, find_packages

setup(
    name="cryptovault",
    version="1.0.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "cryptography>=41.0.0",
        "argon2-cffi>=23.1.0",
        "pyotp>=2.9.0",
        "qrcode>=7.4.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "cryptovault=main:main",
        ]
    },
    python_requires=">=3.10",
    author="Your Team Name",
    description="A comprehensive cryptographic security suite",
)