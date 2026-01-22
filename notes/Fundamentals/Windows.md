
# cmd

```cmd
powershell								# Opens powershell
powershell -command "<PS command>"		# Exectes PS command
```

# Powershell

```powershell
start cmd.exe				# Opens cmd
cmd /c "<CMD Command>"		# Execute CMD command
```

There are two execution 32/64-Bit, cometimes you might need to switch:

- `c:\windows\syswow64\windowspowershell\v1.0\powershell.exe`
- `c:\windows\sysnative\windowspowershell\v1.0\powershell.exe`
## Powershell scripts
Load every function of a script: `ipmo .\[PS1 FILE]`

# User properties
- Get SID
	- `{powershell} Get-ADUser -Identity <username> | select SID`
	- `{cmd} wmic useraccount where name='<username>' get sid`