#!/usr/bin/env python
from setuptools import setup, find_packages
import os


data_files = [(d, [os.path.join(d, f) for f in files])
              for d, folders, files in os.walk(os.path.join('src', 'config'))]


setup(name='qconnector',
      version='1.0',
      description='qualys scan results->postgres',
      author='Adam Pridgen',
      author_email='apridgen@roblox.com',
      install_requires=["requests", "certifi", "xmltodict", "sqlalchemy", "flask",],
      packages=find_packages('src'),
      package_dir={'': 'src'},
)
