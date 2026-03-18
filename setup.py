from setuptools import setup

setup(
    name="matrix-synapse-radius",
    version="0.1.0",
    description="RADIUS authentication provider for Matrix Synapse",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="thelast.pro",
    url="https://github.com/yourusername/matrix-synapse-radius",
    license="Apache-2.0",
    py_modules=["radius_auth_provider"],
    python_requires=">=3.8",
    install_requires=[
        "pyrad>=2.4",
        "matrix-synapse",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Topic :: Communications :: Chat",
    ],
)
