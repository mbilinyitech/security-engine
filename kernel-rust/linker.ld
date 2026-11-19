/* Physical layout the boot code assumes: everything identity-mapped from 1 MiB up. */
ENTRY(_start)

SECTIONS
{
    . = 1M;

    /* Multiboot2 must find its header inside the first 32768 bytes of the file. */
    .boot :
    {
        KEEP(*(.boot_first))
    }

    .note.Xen : ALIGN(4)
    {
        KEEP(*(.note.Xen))
    }

    .text : ALIGN(4096)
    {
        *(.text.boot)
        *(.text .text.*)
    }

    .rodata : ALIGN(4096)
    {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4096)
    {
        *(.data .data.*)
    }

    .bss : ALIGN(4096)
    {
        *(COMMON)
        *(.bss .bss.*)
    }

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.comment)
        *(.note*)
    }
}
