#![no_std]

use mycelium_network_types::{
    LinkState, ObservationCoverage, PortId, PortKind, PortState, VlanId, VlanMembership,
    VlanTagging,
};

pub const BOOT_MARKER_ADDRESS: usize = 0x2000_0f00;
pub const MAILBOX_ADDRESS: usize = 0x2000_0e00;
pub const BOOT_MAGIC: u32 = u32::from_le_bytes(*b"MYC4");
pub const MAILBOX_MAGIC: u32 = u32::from_le_bytes(*b"CMD4");
pub const ABI_VERSION: u32 = 3;
pub const VECTOR_COUNT: u32 = 8;
pub const LOAD_ADDRESS: u32 = 0x2000_1000;
pub const SRAM_BASE: u32 = 0x2000_0000;
pub const SRAM_SIZE: u32 = 0x10_0000;
pub const MAXIMUM_PAYLOAD_SIZE: u32 = 0x0b_f000;
pub const UART_BASE: u32 = 0xc000_0000;
pub const UART_DATA_OFFSET: u32 = 0xf0;
pub const UART_STATUS_OFFSET: u32 = 0xf5;
pub const UART_TX_READY_MASK: u8 = 1 << 5;
pub const HIGH_RES_TIMER_ADDRESS: usize = 0xc000_0098;
pub const NETWORK_SNAPSHOT_ADDRESS: usize = 0x2000_0c00;
pub const NETWORK_SNAPSHOT_VERSION: u32 = 1;
pub const NETWORK_PORTS_PER_PAGE: usize = 8;
pub const NETWORK_VLANS_PER_PAGE: usize = 8;
pub const NETWORK_MEMBERSHIPS_PER_PAGE: usize = 16;
pub const UMAC0_BASE: u32 = 0xc000_4000;
pub const UMAC1_BASE: u32 = 0xc000_5000;
pub const UMAC0_MDIO_COMMAND: u32 = 0xc000_4080;
pub const UMAC0_MDIO_DATA: u32 = 0xc000_4084;
pub const UMAC_DMA_ENTRIES: u32 = 32;
pub const UMAC_DESCRIPTOR_SIZE: u32 = 16;
pub const UMAC_RX_RING_OFFSET: u32 = 0x200;
pub const UMAC_DESCRIPTOR_OWNERSHIP_BIT: u32 = 15;
pub const UMAC_DESCRIPTOR_BUFFER_OFFSET: u32 = 0;
pub const UMAC_DESCRIPTOR_STATUS_OFFSET: u32 = 4;
pub const UMAC_DESCRIPTOR_LENGTH_OFFSET: u32 = 6;
pub const UMAC_DESCRIPTOR_AUX_OFFSET: u32 = 8;
pub const UMAC_DESCRIPTOR_CONTEXT_OFFSET: u32 = 12;
pub const UMAC_DMA_KICK_OFFSET: u32 = 0x08;
pub const UMAC_DMA_IRQ_STATUS_OFFSET: u32 = 0x30;
pub const UMAC_DMA_IRQ_TX_COMPLETE: u32 = 1 << 0;
pub const UMAC_DMA_IRQ_RX_COMPLETE: u32 = 1 << 2;
pub const UMAC_DMA_IRQ_HANDLED_MASK: u32 = 0xd5;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    None = 0,
    Identity = 1,
    Status = 2,
    MemoryMap = 3,
    HighResTimer = 4,
    NetworkMap = 5,
    DmaLayout = 6,
    DmaControl = 7,
}

impl Command {
    pub const fn from_raw(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Identity),
            2 => Some(Self::Status),
            3 => Some(Self::MemoryMap),
            4 => Some(Self::HighResTimer),
            5 => Some(Self::NetworkMap),
            6 => Some(Self::DmaLayout),
            7 => Some(Self::DmaControl),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mailbox {
    pub magic: u32,
    pub sequence: u32,
    pub command: u32,
    pub status: u32,
    pub values: [u32; 4],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanRecord {
    pub id: VlanId,
    /// Firmware-local stable label identifier. Human-readable labels remain a
    /// host concern and may be fetched through a target-specific string table.
    pub label_id: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkSnapshotPage {
    pub version: u32,
    pub sequence: u32,
    pub coverage: ObservationCoverage,
    /// Zero means this is the final page.
    pub next_cursor: u16,
    pub port_count: u8,
    pub vlan_count: u8,
    pub membership_count: u8,
    pub reserved: [u8; 3],
    pub ports: [PortState; NETWORK_PORTS_PER_PAGE],
    pub vlans: [VlanRecord; NETWORK_VLANS_PER_PAGE],
    pub memberships: [VlanMembership; NETWORK_MEMBERSHIPS_PER_PAGE],
}

impl NetworkSnapshotPage {
    pub const fn empty(sequence: u32) -> Self {
        const EMPTY_PORT: PortState = PortState {
            id: PortId(0),
            kind: PortKind::Unknown,
            link: LinkState::Unknown,
            pvid: 0,
        };
        const EMPTY_VLAN: VlanRecord = VlanRecord {
            id: VlanId::DEFAULT,
            label_id: 0,
        };
        const EMPTY_MEMBERSHIP: VlanMembership = VlanMembership {
            port: PortId(0),
            vlan: EMPTY_VLAN.id,
            tagging: VlanTagging::Untagged,
        };
        Self {
            version: NETWORK_SNAPSHOT_VERSION,
            sequence,
            coverage: ObservationCoverage::empty(),
            next_cursor: 0,
            port_count: 0,
            vlan_count: 0,
            membership_count: 0,
            reserved: [0; 3],
            ports: [EMPTY_PORT; NETWORK_PORTS_PER_PAGE],
            vlans: [EMPTY_VLAN; NETWORK_VLANS_PER_PAGE],
            memberships: [EMPTY_MEMBERSHIP; NETWORK_MEMBERSHIPS_PER_PAGE],
        }
    }
}

pub const MAILBOX_WORDS: usize = core::mem::size_of::<Mailbox>() / 4;
pub const STATUS_PENDING: u32 = 0;
pub const STATUS_COMPLETE: u32 = 1;
pub const STATUS_UNKNOWN_COMMAND: u32 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_decoder_is_closed_and_deterministic() {
        assert_eq!(Command::from_raw(4), Some(Command::HighResTimer));
        assert_eq!(Command::from_raw(6), Some(Command::DmaLayout));
        assert_eq!(Command::from_raw(7), Some(Command::DmaControl));
        assert_eq!(Command::from_raw(8), None);
        assert_eq!(Command::from_raw(u32::MAX), None);
    }

    #[test]
    fn mailbox_layout_is_stable() {
        assert_eq!(MAILBOX_WORDS, 8);
        assert_eq!(core::mem::align_of::<Mailbox>(), 4);
    }

    #[test]
    fn network_snapshot_page_is_bounded_and_versioned() {
        let page = NetworkSnapshotPage::empty(7);
        assert_eq!(page.version, NETWORK_SNAPSHOT_VERSION);
        assert_eq!(page.sequence, 7);
        assert_eq!(page.next_cursor, 0);
        assert!(core::mem::size_of::<NetworkSnapshotPage>() <= 512);
        assert_eq!(core::mem::align_of::<NetworkSnapshotPage>(), 4);
    }
}
