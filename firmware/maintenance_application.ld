/* nRF51422 application layout with S130 occupying flash below 0x1b000. */
ENTRY(Reset_Handler)

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x0001b000, LENGTH = 0x00021000
    SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 0x00008000
}

SECTIONS
{
    .isr_vector :
    {
        KEEP(*(.isr_vector))
    } > FLASH

    .text :
    {
        KEEP(*(.text.maintenance_command))
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
    } > FLASH

    .data :
    {
        *(.data*)
        . = ALIGN(4);
    } > SRAM AT > FLASH

    .bss (NOLOAD) :
    {
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
    } > SRAM

    /DISCARD/ :
    {
        *(.ARM.exidx*)
        *(.comment*)
        *(.note*)
    }
}
