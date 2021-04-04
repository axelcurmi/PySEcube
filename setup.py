from setuptools import setup

setup(
    name="PySEcube",
    version="2.0.1",
    description="SEcube L0 and L1 host libraries python wrapper",
    author="Axel Curmi",
    author_email="axel.curmi.20@um.edu.mt",
    url="https://github.com/Axel-Curmi/MScPySEcube",
    packages=["pysecube"],
    setup_requires=["cffi"],
    install_requires=["cffi"],
    cffi_modules=["build_cffi.py:ffi"],
)