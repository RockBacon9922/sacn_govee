use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // SACN multicast address for universe 1
    let multicast_addr = "239.255.0.6:5568".parse::<SocketAddr>()?;

    // Bind socket to listen on all interfaces on port 5568
    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5568);
    let socket = UdpSocket::bind(local_addr).await?;

    // Join multicast group
    if let IpAddr::V4(multicast_v4) = multicast_addr.ip() {
        socket.join_multicast_v4(multicast_v4, Ipv4Addr::UNSPECIFIED)?;
    } else {
        panic!("Only IPv4 is supported in this example.");
    }

    println!("Listening for SACN packets on {}", multicast_addr);

    let mut buf = [0u8; 1500];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;

        if len < 126 {
            // SACN packet minimum size ~126 bytes
            println!("Packet too short to be SACN");
            continue;
        }

        // Validate SACN packet root layer preamble size and ACN Packet Identifier "ASC-E1.17"
        let preamble_size = u16::from_be_bytes([buf[0], buf[1]]);
        let acn_pid = &buf[4..16];
        if preamble_size != 0x0010 || acn_pid != b"ASC-E1.17\0\0\0" {
            println!("Not a valid SACN packet");
            continue;
        }

        // Universe is at root layer + framing layer offset:
        // Root layer = 38 bytes
        // Framing layer starts at 38
        // Universe is at framing layer offset 113 and 114 (big endian)
        let universe = u16::from_be_bytes([buf[113], buf[114]]);

        // DMX data length is at start of DMP layer at offset 115 and 116 (big endian)
        let dmp_length = u16::from_be_bytes([buf[115], buf[116]]) & 0x0FFF; // lower 12 bits

        // DMX start code is at offset 125, DMX data starts at 126
        let dmx_data = &buf[126..len.min(126 + (dmp_length as usize) - 1)];

        // if a8 to ef are full of 0x64 then drop the packet
        if buf[168..200].iter().all(|&x| x == 100) {
            continue;
        }
        println!("Received {} bytes from {}", len, addr);

        println!("Universe: {}", universe);
        println!("DMX data length: {}", dmx_data.len());
        println!(
            "First 10 DMX channels: {:?}",
            &dmx_data[..dmx_data.len().min(10)]
        );
    }
}
