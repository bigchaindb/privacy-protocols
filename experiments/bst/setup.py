"""bst: BigchainDB Sharing Tools"""

from setuptools import setup, find_packages


install_requires = [
    'base58~=0.2.2',
    'PyNaCl~=1.1.0',
    'bigchaindb-driver',
    'click==6.7',
    'colorama',
]

setup(
    name='bst',
    version='0.1.0',
    description='bst: BigchainDB Sharing Tools',
    long_description=(
        'A collection of scripts with different patterns to share'
        'private data on BigchainDB.'),
    url='https://github.com/vrde/bst/',
    author='Alberto Granzotto',
    author_email='alberto@bigchaindb.com',
    license='AGPLv3',
    zip_safe=False,

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Database',
        'Topic :: Database :: Database Engines/Servers',
        'Topic :: Software Development',
        'Natural Language :: English',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
    ],

    packages=find_packages(),

    entry_points={
        'console_scripts': [
            'bst=bst.cli:main'
        ],
    },

    install_requires=install_requires
)
