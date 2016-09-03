bin:
	nasm -f bin -o omelet.bin w32-seh-omelet-shellcode.asm -w+error

fix:
	nasm -f bin -o omelet.bin corefix.asm -w+error

eggs:
	python create_scbin.py
	python w32-seh-omelet-shellcode.py omelet.bin sc.bin calc_eggs.txt 127 0xBAD55

clean:
	rm *.bin
