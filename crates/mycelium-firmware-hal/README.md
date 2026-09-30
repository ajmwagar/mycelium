# mycelium-firmware-hal

Small `no_std` capability contracts for replacement firmware. This crate owns
interfaces, not register maps or protocol behavior.

- Platform crates implement packet I/O, interrupts, storage, clocks, consoles,
  reset, MDIO, sensors, fans, watchdogs, and host-power control using their
  actual hardware boundary.
- Protocol and service crates consume only the traits they require.
- Mycelium drivers consume higher-level device capabilities and never access
  these low-level interfaces directly.

Descriptor layouts, MMIO addresses, cache rules, and ROM callbacks remain in
target-specific crates. Unsupported peripherals do not require dummy methods.
Safety and management policy lives in `mycelium-firmware-services` above this
mechanism-only boundary.

`PacketIo::packet_layer` prevents unlike transports from being conflated:
iLO4 exposes Ethernet frames, while the current Broadlink emulator boundary
exposes application datagrams. A protocol service must require the layer it
actually understands. The eventual RTL8710BX ROM/TCP-IP adapter can preserve
the datagram contract without pretending it is the same as a raw MAC.

Current adopters:

| Target | Shared contracts | Target-owned details |
| --- | --- | --- |
| iLO4 HAL/payload/emulator | `PacketIo`, `InterruptSource`, `MonotonicClock`, `Console` | UMAC descriptors, ownership bits, IRQ masks, timer/UART MMIO |
| Broadlink RM4 firmware | `PacketIo` | INIC/netmock descriptors, MMIO, ROM networking handoff |
