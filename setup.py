# https://click.palletsprojects.com/en/stable/setuptools/#setuptools-integration
# pip install --editable .

from setuptools import setup

setup(
    name='cminfo',
    version='1.0.0 rc1',
    py_modules=['cminfo'],
    install_requires=[
        'click',
        'json',
        'python-dotenv',
        'requests',
        'rich',
        'tqdm',
        'urllib3'
    ],
    entry_points={
        'console_scripts': [
            'cminfo = cminfo:cli',
        ],
    },
)
