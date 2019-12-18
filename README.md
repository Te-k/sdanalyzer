# sdanalyzer

Tool to analyze snoopdroid dumps

## Installation

Download the code from the git repository, then do :

```
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

## TODO

* Export results to CSV / PDF for archive
* Check apps with Yara rules for known android malware
* Comments ?

## License

This code is released un GPLv3 license.
