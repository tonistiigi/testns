# eabi
	.global _start
	.text
_start:
	mov %r7, $0x1d
	swi 0x0

