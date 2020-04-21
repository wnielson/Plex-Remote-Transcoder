from setuptools import setup, find_packages

from codecs import open
from os import path
import re

here = path.abspath(path.dirname(__file__))

def get_version():
    return re.search("__version__ = \"([\d\.]+)\"", open("prt3.py").read()).groups()[0]

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='prt3',
    version=get_version(),
    description='A remote transcoder for Plex(3)',
    long_description=long_description,
    url='https://github.com/wnielson/Plex-Remote-Transcoder',
    author='Weston Nielson',
    author_email='wnielson@github',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='plex media server, distributed plex, load balancing, remote transcoding',
    py_modules=["prt3"],
    entry_points={
        'console_scripts': [
            'prt3=prt3:main',
            'prt3_local=prt3:transcode_local',
            'prt3_remote=prt3:transcode_remote'
        ],
    },
    install_requires=['termcolor', 'psutil']
)
