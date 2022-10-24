# AmsiScanBuffer
Digging deeper into AmsiScanBuffer internals, and identifying 7 possibles AMSI patching by forcing a conditional jump to a branch that sets the return value of AmsiScanBuffer to E_INVALIDARG and makes the AmsiScanBuffer fails
## Tested on Windows 10.  

![FAILED](https://user-images.githubusercontent.com/110354855/197488206-ef33a11f-c2be-4e51-9860-377e3e37dd10.png)

![Patches](https://user-images.githubusercontent.com/110354855/197488268-70e975f1-7eab-4cf3-8c33-b040ebe405c1.png)
