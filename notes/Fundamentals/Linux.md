
# Minimal Shells
**Bash command** (for broken shells) `bash -c "<command>"`
## EOF Writing

Useful to write a file without a text editor
```bash
cat << EOF > [OUTPUT]
[WRITE_CONTENT_HERE]
EOF
```
# Scripting Basics
### Scripts
 - Bash header: `#!/bin/bash`
  - Execute bash script: `chmod +x [FILE]` &rarr; `./[FILE]`
  - C compile: `gcc file.c -o file` &rarr; `./file`
## Terminal 

 **While loop:** 
```bash
while true; do []; done
```
**For Loop:**
```bash
for i in {0..500} ; do [${i}]; done
```
## Bypassing File Permissions
Folder with `rwx` and File with `r--`
1. `mv [FILE] [FILE.bak]`
2. `cp [FILE.bak] [FILE]`
3. `nano [FILE]`
# Errors
- child process exited with exit code 2 -> wrap the payload in `bash -c '[payload]'`