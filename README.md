Put yout kleenscan API key in ~/.kleenscan

Check against Microsoft Defender by default with `avscan malware.exe`

```
usage: avscan [-h] [-avs ANTIVIRUSES] [-l] [-o OUTPUT] [filename]

Scan a file with Kleenscan

positional arguments:
  filename              Path to the file to scan

options:
  -h, --help            show this help message and exit
  -avs ANTIVIRUSES, --antiviruses ANTIVIRUSES
                        Comma-separated list of antiviruses to use (default: microsoftdefender)
  -l, --list            List available antivirus engines
  -o OUTPUT, --output OUTPUT
                        Save scan results to a JSON file
```

<img width="2282" height="930" alt="image" src="https://github.com/user-attachments/assets/88db01c8-57db-43d1-97a4-5c7984abb85e" />

