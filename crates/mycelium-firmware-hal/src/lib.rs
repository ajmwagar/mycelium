#![no_std]
#![forbid(unsafe_code)]

//! Narrow capability contracts shared by replacement-firmware targets.
//!
//! These traits describe useful operations rather than registers or device
//! families. Target crates own MMIO, descriptor encoding, cache maintenance,
//! and interrupt routing below this boundary.

pub use mycelium_network_types::LinkState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketLayer {
    EthernetFrame,
    ApplicationDatagram,
}

pub trait PacketRx {
    type Error;

    /// Receives one complete link-layer frame without blocking.
    fn try_receive(&mut self, output: &mut [u8]) -> Result<Option<usize>, Self::Error>;
}

pub trait PacketTx {
    type Error;

    /// Queues one complete link-layer frame without blocking.
    fn try_transmit(&mut self, frame: &[u8]) -> Result<(), Self::Error>;
}

pub trait PacketIo: PacketRx + PacketTx<Error = <Self as PacketRx>::Error> {
    fn packet_layer(&self) -> PacketLayer;
    fn link_state(&self) -> LinkState;
    fn maximum_frame_size(&self) -> usize;
}

pub trait InterruptSource {
    type Mask: Copy;

    fn pending(&self) -> Self::Mask;
    fn acknowledge(&mut self, mask: Self::Mask);
}

pub trait MonotonicClock {
    type Instant: Copy + Ord;

    fn now(&self) -> Self::Instant;
}

pub trait Console {
    type Error;

    fn try_read(&mut self) -> Result<Option<u8>, Self::Error>;
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}

pub trait Reset {
    fn reset(&mut self) -> !;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageGeometry {
    pub capacity: u32,
    pub erase_size: u32,
    pub program_size: u32,
}

pub trait BlockStorage {
    type Error;

    fn geometry(&self) -> StorageGeometry;
    fn read(&self, offset: u32, output: &mut [u8]) -> Result<(), Self::Error>;
    fn erase(&mut self, offset: u32, length: u32) -> Result<(), Self::Error>;
    fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), Self::Error>;
}

pub trait ConfigStore {
    type Error;

    fn load(&self, output: &mut [u8]) -> Result<Option<usize>, Self::Error>;
    fn store(&mut self, value: &[u8]) -> Result<(), Self::Error>;
}

pub trait MdioBus {
    type Error;

    fn read(&mut self, phy: u8, register: u8) -> Result<u16, Self::Error>;
    fn write(&mut self, phy: u8, register: u8, value: u16) -> Result<(), Self::Error>;
}

/// A temperature channel expressed in milli-degrees Celsius.
pub trait TemperatureSensor {
    type Error;

    fn read_millidegrees_celsius(&mut self) -> Result<i32, Self::Error>;
}

/// One independently controlled fan channel.
pub trait FanControl {
    type Error;

    fn set_duty_percent(&mut self, duty_percent: u8) -> Result<(), Self::Error>;
    fn tachometer_rpm(&mut self) -> Result<u32, Self::Error>;
}

pub trait Watchdog {
    type Error;

    fn pet(&mut self) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPowerState {
    Off,
    On,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPowerAction {
    MomentaryPower,
    GracefulShutdown,
    ForceOff,
    Reset,
    PowerCycle,
}

/// Electrical host-control operations. State policy belongs above this trait.
pub trait HostPowerControl {
    type Error;

    fn state(&mut self) -> Result<HostPowerState, Self::Error>;
    fn perform(&mut self, action: HostPowerAction) -> Result<(), Self::Error>;
}
