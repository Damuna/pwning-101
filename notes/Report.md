# Findings

## Reflected XSS
Upon requesting the link:
```
https://yourdailygerman.com/dictionary/?dictionary=1&s=test'"><img+src%3Dx+onerror%3Dalert(document.domain)><
```
The domain of the page is revealed, showing a reflected  XSS injection.
![[Pasted image 20260218173949.png]]

Reflected XSS allows account takeover by sending a malicious link containing JavaScript code that will be executed in the victim's browser while they are logged in.

### Remediation
Reflected strings should be sanitized to prevent execution of JavaScript code.

