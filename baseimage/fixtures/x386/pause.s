	.global _start
	.text
_start:
	mov $0x1d, %eax
	int $0x80
