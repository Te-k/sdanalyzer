from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='sdanalyzer',
    version='0.1.1',
    description='Tool to analyze snoopdroid dump',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/Te-k/sdanalyzer',
    author='Tek',
    author_email='tek@randhome.io',
    keywords='osint',
    include_package_data=True,
    install_requires=[
        'Flask==1.1.1',
        'Flask-WTF==0.14.3',
        'peewee==3.13.2',
        'androguard==3.3.5',
        'requests'
        ],
    python_requires='>=3.5',
    license='GPLv3',
    packages=['sdanalyzer', 'sdanalyzer.templates', 'sdanalyzer.data'],
    package_data={'sdanalyzer': ['sdanalyzer/data/*', 'sdanalyzer/templates/*']},
    entry_points= {
        'console_scripts': [ 'sdanalyzer=sdanalyzer.main:main' ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
