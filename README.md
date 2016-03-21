# ntfs-journal-viewer
Utterly simple NTFS Journal dumping utility. Handy when it comes to Computer Forensics and Malware Forensics Ops.

Kinda old stuff from my HDD, but still gets it's job done.

## Usage
```

Journal v1.0 - NTFS change journal records lister
Mariusz B., 2012 - MGeeky@gmail.com


Usage:  journal [options] <drive>
Where:
        <drive>         - is a drive letter with a colon (i.e. C:)
Options:
        -c              - prints only filenames (requires specify '-d' switch)
        -d              - dump entire journal (huge amount of data!)
        -f <name>       - find specified <name> in USN entries filenames
        -t <timestamp>  - dump records with specified <timestamp>
                          (hex / yyyy-mm-dd[:hh:MM:ss[.mili]] format,
                          tip: use 99 as a wildcard)
        -u <USN>        - dump specified <USN> record
```
