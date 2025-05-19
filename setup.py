from setuptools import setup, find_packages

setup(
    name="ssh-botnet-controller",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "pexpect>=4.8.0",
        "scapy>=2.4.5",
        "cryptography>=36.0.0",
    ],
    python_requires='>=3.6',
    description="Educational SSH Botnet Controller",
    author="Sagar Karatagi",
    author_email="venomxsagar@gmail.com",
    url="https://github.com/sagar-karatagi/SSH-Botnet",
)
