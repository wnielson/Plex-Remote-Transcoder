from setuptools import setup, find_packages

from codecs import open
from os import path
import re

here = path.abspath(path.dirname(__file__))

def get_version():
    return re.search("__version__ = \"([\d\.]+)\"", open("prt.py").read()).groups()[0]

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='prt',
    version=get_version(),
    description='A remote transcoder for Plex',
    long_description=long_description,
    url='https://github.com/wnielson/Plex-Remote-Transcoder',
    author='Weston Nielson',
    author_email='wnielson@github',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='plex media server, distributed plex, load balancing, remote transcoding',
    py_modules=["prt"],
    entry_points={
        'console_scripts': [
            'prt=prt:main',
            'prt_local=prt:transcode_local',
            'prt_remote=prt:transcode_remote'
        ],
    },
    install_requires=['termcolor']
)
