from setuptools import setup, find_packages

setup(
    name="gcp-misconfig-scanner",
    version="1.0.0",
    description="GCP misconfiguration scanner with Terraform remediation and ELK integration",
    author="Garvit Kohli",
    packages=find_packages(),
    install_requires=[
        "google-auth>=2.23.0",
        "google-auth-httplib2>=0.2.0",
        "google-api-python-client>=2.108.0",
        "google-cloud-storage>=2.10.0",
        "click>=8.1.7",
        "rich>=13.5.2",
        "pyyaml>=6.0.1",
        "requests>=2.31.0",
        "python-dateutil>=2.8.2",
    ],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "gcp-scan=cli:cli",
        ],
    },
)
