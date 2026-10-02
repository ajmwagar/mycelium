use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use serde::Serialize;
use tokio::net::UdpSocket;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const MAGIC_COOKIE: u32 = 0x2112_A442;
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ProbeResult {
    pub server: String,
    pub source: SocketAddr,
    pub mapped: SocketAddr,
    pub latency_ms: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ProbeReport {
    pub bind: Option<IpAddr>,
    pub results: Vec<ProbeResult>,
    pub failures: Vec<String>,
    pub public_ip_stable: bool,
    pub mapping_varies_by_destination: bool,
}

pub(crate) async fn probe_many(
    servers: &[String],
    bind: Option<IpAddr>,
    source_port: u16,
) -> ProbeReport {
    let mut results = Vec::new();
    let mut failures = Vec::new();
    let mut source = bind.map(|address| SocketAddr::new(address, source_port));
    for server in servers {
        match probe(server, source).await {
            Ok(result) => {
                source = Some(result.source);
                results.push(result);
            }
            Err(error) => failures.push(error),
        }
    }
    let mapped_ips = results
        .iter()
        .map(|result| result.mapped.ip())
        .collect::<std::collections::BTreeSet<_>>();
    let mapped_endpoints = results
        .iter()
        .map(|result| result.mapped)
        .collect::<std::collections::BTreeSet<_>>();
    ProbeReport {
        bind,
        public_ip_stable: mapped_ips.len() == 1,
        mapping_varies_by_destination: mapped_endpoints.len() > 1,
        results,
        failures,
    }
}

pub(crate) async fn probe(server: &str, bind: Option<SocketAddr>) -> Result<ProbeResult, String> {
    let mut addresses = tokio::net::lookup_host(server)
        .await
        .map_err(|error| format!("resolve STUN server `{server}`: {error}"))?;
    let destination = addresses
        .find(|address| bind.is_none_or(|bind| bind.is_ipv4() == address.is_ipv4()))
        .ok_or_else(|| format!("STUN server `{server}` has no compatible address"))?;
    let bind = bind.unwrap_or_else(|| {
        SocketAddr::new(
            if destination.is_ipv4() {
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            },
            0,
        )
    });
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|error| format!("bind STUN probe to `{bind}`: {error}"))?;
    socket
        .connect(destination)
        .await
        .map_err(|error| format!("connect STUN server `{destination}`: {error}"))?;
    let source = socket
        .local_addr()
        .map_err(|error| format!("read STUN source address: {error}"))?;
    let mut transaction = [0u8; 12];
    OsRng.fill_bytes(&mut transaction);
    let request = binding_request(transaction);
    let started = std::time::Instant::now();
    socket
        .send(&request)
        .await
        .map_err(|error| format!("send STUN request to `{destination}`: {error}"))?;
    let mut response = [0u8; 2048];
    let length = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut response))
        .await
        .map_err(|_| format!("STUN server `{destination}` timed out"))?
        .map_err(|error| format!("receive STUN response from `{destination}`: {error}"))?;
    let mapped = parse_binding_response(&response[..length], transaction)?;
    Ok(ProbeResult {
        server: server.into(),
        source,
        mapped,
        latency_ms: started.elapsed().as_millis(),
    })
}

fn binding_request(transaction: [u8; 12]) -> [u8; 20] {
    let mut request = [0u8; 20];
    request[..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    request[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    request[8..20].copy_from_slice(&transaction);
    request
}

fn parse_binding_response(bytes: &[u8], transaction: [u8; 12]) -> Result<SocketAddr, String> {
    if bytes.len() < 20 {
        return Err("STUN response is shorter than its header".into());
    }
    if u16::from_be_bytes([bytes[0], bytes[1]]) != BINDING_SUCCESS {
        return Err("STUN response is not a successful binding response".into());
    }
    if u32::from_be_bytes(bytes[4..8].try_into().unwrap()) != MAGIC_COOKIE {
        return Err("STUN response has the wrong magic cookie".into());
    }
    if bytes[8..20] != transaction {
        return Err("STUN response transaction ID does not match the request".into());
    }
    let declared = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if declared + 20 > bytes.len() {
        return Err("STUN response has a truncated attribute section".into());
    }
    let mut offset = 20;
    while offset + 4 <= 20 + declared {
        let kind = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let length = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        let start = offset + 4;
        let end = start + length;
        if end > bytes.len() {
            return Err("STUN response contains a truncated attribute".into());
        }
        if kind == XOR_MAPPED_ADDRESS || kind == MAPPED_ADDRESS {
            return parse_mapped_address(
                &bytes[start..end],
                kind == XOR_MAPPED_ADDRESS,
                transaction,
            );
        }
        offset = end + ((4 - length % 4) % 4);
    }
    Err("STUN response has no mapped-address attribute".into())
}

fn parse_mapped_address(
    value: &[u8],
    xor: bool,
    transaction: [u8; 12],
) -> Result<SocketAddr, String> {
    if value.len() < 4 {
        return Err("STUN mapped address is truncated".into());
    }
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }
    let address = match value[1] {
        0x01 if value.len() >= 8 => {
            let mut octets: [u8; 4] = value[4..8].try_into().unwrap();
            if xor {
                for (byte, mask) in octets.iter_mut().zip(MAGIC_COOKIE.to_be_bytes()) {
                    *byte ^= mask;
                }
            }
            IpAddr::V4(octets.into())
        }
        0x02 if value.len() >= 20 => {
            let mut octets: [u8; 16] = value[4..20].try_into().unwrap();
            if xor {
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                mask[4..].copy_from_slice(&transaction);
                for (byte, mask) in octets.iter_mut().zip(mask) {
                    *byte ^= mask;
                }
            }
            IpAddr::V6(octets.into())
        }
        family => return Err(format!("unsupported STUN address family {family}")),
    };
    Ok(SocketAddr::new(address, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_xor_mapped_ipv4_and_checks_transaction() {
        let transaction = [7u8; 12];
        let mapped = SocketAddr::new("203.0.113.9".parse().unwrap(), 51820);
        let mut response = vec![0u8; 32];
        response[..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        response[2..4].copy_from_slice(&12u16.to_be_bytes());
        response[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response[8..20].copy_from_slice(&transaction);
        response[20..22].copy_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        response[22..24].copy_from_slice(&8u16.to_be_bytes());
        response[25] = 0x01;
        let port = mapped.port() ^ (MAGIC_COOKIE >> 16) as u16;
        response[26..28].copy_from_slice(&port.to_be_bytes());
        let ip = match mapped.ip() {
            IpAddr::V4(ip) => ip.octets(),
            _ => unreachable!(),
        };
        for (index, mask) in MAGIC_COOKIE.to_be_bytes().into_iter().enumerate() {
            response[28 + index] = ip[index] ^ mask;
        }
        assert_eq!(
            parse_binding_response(&response, transaction).unwrap(),
            mapped
        );
        assert!(parse_binding_response(&response, [8u8; 12]).is_err());
    }

    #[test]
    fn binding_request_is_rfc5389_shaped() {
        let transaction = [3u8; 12];
        let request = binding_request(transaction);
        assert_eq!(&request[..2], &BINDING_REQUEST.to_be_bytes());
        assert_eq!(&request[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&request[8..], &transaction);
    }
}
