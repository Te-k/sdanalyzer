# snoopdroid-analyzer

Tool to analyze snoopdroid dumps

## TODO

* Create projects
* Manifest, VT, certificate, Koodous etc.
* Add bug report analysis
* -> Analyze the last phone
* yara rules from AI
* Summary -> PDF

## Installation

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
sdanalyzer server
```

## License

This code is released un GPLv3 license.
