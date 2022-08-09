from setuptools import find_packages, setup

setup(
    name="dnscryptutils",
    version="0.0.1",
    description="Print out dnsstamp info from sources in your dnscrypt-config.toml configuration file",
    author="goonnowgit",
    author_email="goonnowgittt@gmail.com",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=["dnsstamps", "requests", "toml"],
)
