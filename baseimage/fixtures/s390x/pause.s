# no idea if this works
# http://lars.nocrew.org/computers/processors/ESA390/dz9zr002.pdf
	.global _start
	.text
_start:
	mvi %r1, 0x1d
	svc 0
