"""Setup for AVAGuard Core library."""
from setuptools import setup, find_namespace_packages

setup(
    name="avaguard-core",
    version=open('../VERSION').read().strip(),
    description="Core AVAGuard compliance library",
    packages=find_namespace_packages(include=["avaguard_core*"]),
    include_package_data=True,
    package_data={
        'avaguard_core': ['templates/*.j2'],
    },
    install_requires=[
        'msal>=1.26.0',
        'requests>=2.31.0',
        'azure-identity>=1.15.0',
        'sqlalchemy>=2.0.0',
        'python-dotenv>=1.0.1',
        'jinja2>=3.1.0'
    ],
)
