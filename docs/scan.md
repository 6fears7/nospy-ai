# Scan mode: redact files

[Back to the README](../README.md)

```bash
echo "ssh root@10.0.0.5" | nospy scan
nospy scan --terms terms.txt notes.md
nospy scan --explain notes.md
```

`nospy scan [--terms FILE] [--explain] [FILE...]` reads the files (or stdin; `-` also means stdin), prints the redacted text to stdout and the counts to stderr.

`--explain` prints one line per match instead: `line:col KIND rule "text"`. It shows the values.
