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
        ],
    python_requires='>=3.5',
    license='GPLv3',
    packages=['sdanalyzer'],
    entry_points= {
        'console_scripts': [ 'sdanalyzer=sdanalyzer.main:main' ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
