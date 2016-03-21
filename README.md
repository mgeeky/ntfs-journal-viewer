# ntfs-journal-viewer
Utterly simple NTFS Journal dumping utility. Handy when it comes to Computer Forensics and Malware Forensics Ops.

Kinda old stuff from my HDD, but still gets it's job done.

### Usage
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

### Examples

Listing drive's journal header:
```
d:\>journal.exe C:

Journal v1.0 - NTFS change journal records lister
Mariusz B., 2012 - MGeeky@gmail.com


[?] Examining \\.\C: drive's journal...

Journal data for \\.\C: drive
        UsnJournalID =          01d04afa0272595b
        FirstUsn =              00000001bfc00000
        NextUsn =               00000001c20b5be8
        LowestValidUsn =        0000000000000000
        MaxUsn =                7fffffffffff0000
        MaximumSize =           0000000002000000
        AllocationDelta =       0000000000800000
```

Listing drive's most recently logged files:
```
d:\>journal.exe -c -d C:

Journal v1.0 - NTFS change journal records lister
Mariusz B., 2012 - MGeeky@gmail.com


[?] Examining \\.\C: drive's journal...

Journal data for \\.\C: drive
        UsnJournalID =          01d04afa0272595b
        FirstUsn =              00000001bfc00000
        NextUsn =               00000001c20b92c8
        LowestValidUsn =        0000000000000000
        MaxUsn =                7fffffffffff0000
        MaximumSize =           0000000002000000
        AllocationDelta =       0000000000800000

QEHWF0EBL06ML5W3IG9X.temp
969252ce11249fdd.customDestinations-ms
969252ce11249fdd.customDestinations-ms~RF2cb3cd09.TMP
969252ce11249fdd.customDestinations-ms
969252ce11249fdd.customDestinations-ms~RF2cb3cd09.TMP
glasswire.db-journal
glasswire.db-journal
glasswire.db-journal
glasswire.db-journal
glasswire.db-journal
glasswire.db-journal
glasswire.db-journal
glasswire.db-journal
glasswire.db-journal
glasswire.db-journal
Microsoft-Windows-Store%4Operational.evtx
appdb.dat
edb.log
{33bf9da8-5548-486b-af96-bcee52c3f76b}
{33bf9da8-5548-486b-af96-bcee52c3f76b}
{33bf9da8-5548-486b-af96-bcee52c3f76b}.~tmp
{33bf9da8-5548-486b-af96-bcee52c3f76b}.~tmp
AppCache131028784270799380.txt
AppCache131028784270799380.txt
```

Bit more verbose output:
```
d:\> journal.exe -d C:

0c6/5.29: (ret=648)
        USN = 00000001bfc05d48
        FileReferenceNumber = 3b000021f73 (MFT's idx: 139123)
        FileName = bookmarks.json.tmp
        TimeStamp = 1d181fccb169968 (2016-03-19 16:31:30.945)
        SecurityID = 0
        FileAttributes = 0x20
                FILE_ATTRIBUTE_ARCHIVE |
                FILE_ATTRIBUTE_VALID_FLAGS |
                FILE_ATTRIBUTE_VALID_SET_FLAGS
        Reason = 0x1000
                USN_REASON_RENAME_OLD_NAME

0c7/5.30: (ret=552)
        USN = 00000001bfc05da8
        FileReferenceNumber = 3b000021f73 (MFT's idx: 139123)
        FileName = bookmarks.json
        TimeStamp = 1d181fccb169968 (2016-03-19 16:31:30.945)
        SecurityID = 0
        FileAttributes = 0x20
                FILE_ATTRIBUTE_ARCHIVE |
                FILE_ATTRIBUTE_VALID_FLAGS |
                FILE_ATTRIBUTE_VALID_SET_FLAGS
        Reason = 0x2000
                USN_REASON_RENAME_NEW_NAME

0c8/5.31: (ret=464)
        USN = 00000001bfc05e00
        FileReferenceNumber = 3b000021f73 (MFT's idx: 139123)
        FileName = bookmarks.json
        TimeStamp = 1d181fccb169968 (2016-03-19 16:31:30.945)
        SecurityID = 0
        FileAttributes = 0x20
                FILE_ATTRIBUTE_ARCHIVE |
                FILE_ATTRIBUTE_VALID_FLAGS |
                FILE_ATTRIBUTE_VALID_SET_FLAGS
        Reason = 0x80002000
                USN_REASON_CLOSE |
                USN_REASON_RENAME_NEW_NAME

0c9/5.32: (ret=376)
        USN = 00000001bfc05e58
        FileReferenceNumber = 1600002245a (MFT's idx: 140378)
        FileName = addons.json.tmp
        TimeStamp = 1d181fccb1a3028 (2016-03-19 16:31:30.968)
        SecurityID = 0
        FileAttributes = 0x20
                FILE_ATTRIBUTE_ARCHIVE |
                FILE_ATTRIBUTE_VALID_FLAGS |
                FILE_ATTRIBUTE_VALID_SET_FLAGS
        Reason = 0x100
                USN_REASON_FILE_CREATE
```

And USN (Update Sequence Number) specific entry:
```
d:\> journal -u 00000001bfc05e58 C:

Journal v1.0 - NTFS change journal records lister
Mariusz B., 2012 - MGeeky@gmail.com


[?] Examining \\.\C: drive's journal...

Journal data for \\.\C: drive
        UsnJournalID =          01d04afa0272595b
        FirstUsn =              00000001bfc00000
        NextUsn =               00000001c20c5810
        LowestValidUsn =        0000000000000000
        MaxUsn =                7fffffffffff0000
        MaximumSize =           0000000002000000
        AllocationDelta =       0000000000800000

[>] Searching for records with USN = 1bfc05e58


0c9/5.32: (ret=376)
        USN = 00000001bfc05e58
        FileReferenceNumber = 1600002245a (MFT's idx: 140378)
        FileName = addons.json.tmp
        TimeStamp = 1d181fccb1a3028 (2016-03-19 16:31:30.968)
        SecurityID = 0
        FileAttributes = 0x20
                FILE_ATTRIBUTE_ARCHIVE |
                FILE_ATTRIBUTE_VALID_FLAGS |
                FILE_ATTRIBUTE_VALID_SET_FLAGS
        Reason = 0x100
                USN_REASON_FILE_CREATE
```
