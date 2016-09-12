# no idea if this works
# http://www.ds.ewi.tudelft.nl/vakken/in1006/instruction-set/
	.global _start
	.text
_start:
	li %r0, 0x1d
	sc
