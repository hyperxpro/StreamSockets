//! Spawn server + client + UDP echo, send 100 datagrams, assert ≥99 echo.
//!
//! Spec §11.2: "send 100 datagrams, assert echo".
//! Threshold raised from 60% (50 datagrams / ≥30 echoes) → 99% (100 / ≥99) so
//! a regression in the post-handshake first-packet drop window is detectable.

mod common;

use std::time::Duration;

use tokio::net::UdpSocket;

#[tokio::test]
async fn echo_through_tunnel() {
    common::init_tracing_for_tests();

    let server_port = common::free_tcp_port().await;
    let metrics_port = common::free_tcp_port().await;
    let client_udp_port = common::free_udp_port().await;
    let (echo_port, _echo) = common::spawn_udp_echo().await;

    let yaml = common::default_accounts_yaml(echo_port);
    let accounts = common::write_accounts(&yaml);

    let _server =
        common::spawn_server(server_port, accounts.path().to_path_buf(), metrics_port).await;

    let cfg = common::default_client_cfg(server_port, client_udp_port, echo_port);
    let (_client, _shutdown) = common::spawn_client(cfg).await;
    common::settle(Duration::from_millis(300)).await;

    // Send one warm-up packet to flush the listener-lock-on + first WS dial,
    // then count strict echo on the remaining 100 packets.
    let game = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target: std::net::SocketAddr = format!("127.0.0.1:{client_udp_port}").parse().unwrap();

    game.send_to(b"warmup", target).await.unwrap();
    let mut buf = [0u8; 64];
    let _ = tokio::time::timeout(Duration::from_secs(3), game.recv_from(&mut buf)).await;
    common::settle(Duration::from_millis(100)).await;

    let mut received = 0u32;
    for i in 0..100u32 {
        let payload = format!("hello-{i}");
        game.send_to(payload.as_bytes(), target).await.unwrap();
        let mut buf = [0u8; 64];
        // Failing fast on a recv timeout (rather than swallowing it via
        // `_ => {}`) ensures a regression that hangs N receives surfaces
        // immediately instead of degrading the threshold from 99/100 to 0/100
        // silently.
        match tokio::time::timeout(Duration::from_secs(2), game.recv_from(&mut buf)).await {
            Ok(Ok((n, _peer))) => {
                let echoed = std::str::from_utf8(&buf[..n]).unwrap();
                assert_eq!(echoed, payload);
                received += 1;
            }
            Ok(Err(e)) => panic!("recv error for echo {i}: {e}"),
            Err(_) => {
                panic!("recv timeout for echo {i} (sent {payload}, received {received} so far)")
            }
        }
    }
    // Panic-on-first-timeout above means received==100 by construction.
    // Keep belt-and-braces in case the panic is ever softened back to a count.
    assert_eq!(
        received, 100,
        "expected 100 echoes out of 100 (post-warmup), got {received}"
    );
}
