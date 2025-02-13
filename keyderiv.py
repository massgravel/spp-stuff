import re
import json
import sys

"""
Set all following breakpoints on sppsvc.exe in x64dbg with Break Condition 0, Command Condition 1, and the associated Command Text:

For prod key, works on 19041.1266 -> 19044.3803

`sppsvc+1957F4` - `log "MODULUS {mem;0x80@rdx}"`
`sppsvc+195A80` - `log "MUL F1 {mem;0x80@rdx}"; log "MUL F2 {mem;0x80@r8}"`
`sppsvc+1A36F1` - `log "MUL PROD {mem;0x80@rbx}"`
`sppsvc+198CEC` - `log "MPMUL F1 {mem;0x80@[[arg.get(2)]-[[sppsvc+0x440198]]]}"; log "MPMUL F2 {mem;0x80@[[arg.get(3)]-[[sppsvc+0x440198]]]}"`
`sppsvc+199E07` - `log "MPMUL PROD {mem;0x80@[rax-[[sppsvc+0x440198]]]}"`
`sppsvc+19561C` - `log "LAST MPMODMUL"`

For test key, works on 20221.1000

`sppsvc+1DD940` - `log "MODULUS {mem;0x80@rdx}"`
`sppsvc+1DDFF0` - `log "MUL F1 {mem;0x80@rdx}"; log "MUL F2 {mem;0x80@r8}"`
`sppsvc+1DD8B1` - `log "MUL PROD {mem;0x80@rdi}"`
`sppsvc+1D2050` - `log "MPMUL F1 {mem;0x80@[[arg.get(2)]-[[sppsvc+0x483178]]]}"; log "MPMUL F2 {mem;0x80@[[arg.get(3)]-[[sppsvc+0x483178]]]}"`
`sppsvc+1D30F4` - `log "MPMUL PROD {mem;0x80@[[rbp-0x69]-[[sppsvc+0x483178]]]}"`
`sppsvc+1CEDE2` - `log "LAST MPMODMUL"`

Right-click in Log tab, select "Redirect Log File" and choose path before unsuspending, once LAST MPMODMUL is shown then save log file and use with this script.
"""

pows = {}

mul_log = open(sys.argv[1], "r").read()

muls = re.finditer(r"\s*(?:MPMUL|MUL) F1 (\w+)\s*(?:MPMUL|MUL) F2 (\w+)\s*(?:MPMUL|MUL) PROD (\w+)\s*", mul_log, re.DOTALL | re.MULTILINE)
fs_mul = muls.__next__()

assert fs_mul[1] == fs_mul[2]

pows[fs_mul[1]] = 1
pows[fs_mul[3]] = 2

last_pow = 0

for mul in muls:
    print(mul[1][:8], mul[2][:8], mul[3][:8])
    pows[mul[3]] = pows[mul[1]] + pows[mul[2]]
    
    last_pow = pows[mul[3]]

print("Derived private key: ", hex(last_pow))