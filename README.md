# sdanalyzer

Tool to analyze a large number of Android applications easily. It consist of a command line tool extracting data from all applications, storing it in a local database, and then opening a web interface to manually analyze the results in a user-friendly way.

![screenshot](screenshot.png)

## Installation

You can install sdanalyzer directly from [pypi](https://pypi.org/project/sdanalyzer/) : `pip install sdanalyze`.

You can also download the code from the git repository, and install it from the source code :

```
git pull git@github.com:Te-k/sdanalyzer.git
cd sdanalyzer
pip install .
```

## How to use it

**Create a new phone** :

```
sdanalyzer phones --create "Roberto's Phone"
1	Roberto's Phone	None
```

**Import APKs:**
```
sdanalyzer import --phone 1 .
```

**Run the web server to check the APKs:**
```
sdanalyzer serve
```

Once you have done your analysis, you can delete the local database with `sdanalyzer flush`

You can check all the options of the sdanalyzer command :

```
$ sdanalyzer -h
usage: sdanalyzer [-h] {serve,flush,phones,import,delete} ...

Launches sdanalyzer

positional arguments:
  {serve,flush,phones,import,delete}
                        Subcommand
    serve               Launch the web app
    flush               Flush the database
    phones              List phones
    import              Import apks
    delete              Delete a phone and related data
    export              Export information on all apks of a phone

optional arguments:
  -h, --help            show this help message and exit
```

## Infos on how it works

* This tool largely relies on [androguard](https://github.com/androguard/androguard)
* The local database is an sqlite database stored in `~/.config/sdanalyzer/db.db`
* An incomplete list of [trusted APK signing certificates](https://github.com/Te-k/sdanalyzer/blob/master/sdanalyzer/data/trusted_certs.csv) is provided with the tool. It has been built manually and is helpful to quickly sort apps, but it is clearly incomplete so use at your own risk.
* A few yara rules are provided with the tool but if you want to rely on Yara for detection, you are encouraged to provide additional yara rules with the `-y` option to the `sdanalyzer import` command.

Feel free to open issues for new feature ideas or bugs.

## License

This code is released under GPLv3 license.
