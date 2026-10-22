/* SPDX-License-Identifier: MIT
 * Included by stock pe_serial.c after register_serial_functions. QEMU ONLY.
 * PL011 offsets/flags and PrimeCell IDs checked against QEMU v9.2.4 pl011.c.
 * Addresses and uartclk come from the actual QEMU FDT -> ADT, never UMS512.
 * Polled TX/RX only; no IRQ support is advertised.
 */
#include <stdint.h>
struct ums512_uart_proof {
    uint64_t initialized,tx_bytes,rx_bytes,clock_hz,divisor64,physical,size,identity_verified;
};
volatile struct ums512_uart_proof ums512_uart_proof;
SECURITY_READ_ONLY_LATE(static vm_offset_t) qemu_pl011_base;
SECURITY_READ_ONLY_LATE(static uint32_t) qemu_pl011_clock;
static uint32_t qemu_uart_read(unsigned offset)
{ return *(volatile uint32_t *)(qemu_pl011_base+offset); }
static void qemu_uart_write(unsigned offset,uint32_t value)
{
    *(volatile uint32_t *)(qemu_pl011_base+offset)=value;
    __asm__ volatile("dsb sy" ::: "memory");
}
static unsigned qemu_uart_tx_ready(void) { return !(qemu_uart_read(0x18)&0x20); }
static void qemu_uart_tx(uint8_t c)
{ qemu_uart_write(0,c); ums512_uart_proof.tx_bytes++; }
static unsigned qemu_uart_rx_ready(void) { return !(qemu_uart_read(0x18)&0x10); }
static uint8_t qemu_uart_rx(void)
{ ums512_uart_proof.rx_bytes++; return (uint8_t)qemu_uart_read(0); }
static void qemu_uart_init(void)
{
    static const uint8_t identity[]={0x11,0x10,0x14,0x00,0x0d,0xf0,0x05,0xb1};
    for (unsigned i=0;i<8;i++) {
        if ((qemu_uart_read(0xfe0+i*4)&255)!=identity[i]) { panic("QEMU PL011 identity mismatch"); }
    }
    /* baud divisor = uartclk/(16*115200), rounded in 1/64 units. */
    uint64_t divisor=((uint64_t)qemu_pl011_clock*4+57600)/115200;
    if (divisor<64 || divisor>UINT64_C(0x3fffff)) { panic("QEMU PL011 invalid clock divisor"); }
    qemu_uart_write(0x30,0); /* Disable while changing baud/frame configuration. */
    qemu_uart_write(0x38,0); /* Mask all device interrupts: polled console. */
    qemu_uart_write(0x48,0); /* DMA disabled. */
    qemu_uart_write(0x04,0); /* Clear receive error status. */
    qemu_uart_write(0x24,(uint32_t)(divisor>>6));
    qemu_uart_write(0x28,(uint32_t)(divisor&63));
    qemu_uart_write(0x2c,0x70); /* Eight data bits, FIFO, no parity, one stop bit. */
    qemu_uart_write(0x44,0x7ff);
    qemu_uart_write(0x30,0x301); /* UARTEN | TXE | RXE. */
    ums512_uart_proof.identity_verified=1;
    ums512_uart_proof.clock_hz=qemu_pl011_clock;
    ums512_uart_proof.divisor64=divisor;
    ums512_uart_proof.initialized=1;
    /* Bounded real-device TX proof, independent of printf console routing. */
    static const char marker[]="RMX-QEMU: PL011 console ready\n";
    for (unsigned i=0;i<sizeof(marker)-1;i++) {
        unsigned spins=0;
        while (!qemu_uart_tx_ready()) {
            if (++spins==100000) { panic("QEMU PL011 transmit timeout"); }
        }
        qemu_uart_tx((uint8_t)marker[i]);
    }
}
SECURITY_READ_ONLY_LATE(static struct pe_serial_functions) qemu_pl011_functions={
    .init=qemu_uart_init,.transmit_ready=qemu_uart_tx_ready,.transmit_data=qemu_uart_tx,
    .receive_ready=qemu_uart_rx_ready,.receive_data=qemu_uart_rx,.device=SERIAL_QEMU_PL011,
};
static void qemu_pl011_register(vm_offset_t soc_base)
{
    DTEntry root,entry;
    const void *model=NULL,*compatible=NULL;
    const uint64_t *reg=NULL;
    const uint32_t *clock=NULL;
    unsigned length=0;
    static const char qemu[]="qemu,virt",pl011[]="arm,pl011";
    if (SecureDTLookupEntry(NULL,"/",&root)!=kSuccess ||
        SecureDTGetProperty(root,"model",&model,&length)!=kSuccess ||
        length!=sizeof(qemu) || memcmp(model,qemu,sizeof(qemu))) { return; }
    if (SecureDTLookupEntry(NULL,"/arm-io/uart0",&entry)!=kSuccess) { return; }
    if (SecureDTGetProperty(entry,"compatible",&compatible,&length)!=kSuccess ||
        length!=sizeof(pl011) || memcmp(compatible,pl011,sizeof(pl011))) { panic("QEMU PL011 incompatible ADT"); }
    if (SecureDTGetProperty(entry,"reg",(const void **)&reg,&length)!=kSuccess || length!=16 ||
        reg[1]<0x1000 || reg[1]>0x10000 || reg[0]>UINT64_MAX-soc_base ||
        reg[1]>UINT64_MAX-(soc_base+reg[0])) { panic("QEMU PL011 invalid ADT range"); }
    if (SecureDTGetProperty(entry,"clock-frequency",(const void **)&clock,&length)!=kSuccess ||
        length!=4 || *clock<2000000 || *clock>200000000) { panic("QEMU PL011 missing uartclk"); }
    qemu_pl011_clock=*clock;
    ums512_uart_proof.physical=soc_base+reg[0]; ums512_uart_proof.size=reg[1];
    qemu_pl011_base=ml_io_map(soc_base+reg[0],reg[1]);
    if (!qemu_pl011_base) { panic("QEMU PL011 mapping failed"); }
    register_serial_functions(&qemu_pl011_functions);
}
