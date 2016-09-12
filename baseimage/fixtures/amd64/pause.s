	.global _start
	.text
_start:
	mov $0x22, %rax
	syscall
