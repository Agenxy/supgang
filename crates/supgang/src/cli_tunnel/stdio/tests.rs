use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{Pipe, bridge_io};

#[tokio::test]
async fn native_stdio_half_close_waits_for_response_and_peer_eof_cancels_input()
-> Result<(), Box<dyn std::error::Error>> {
    let (input_read, input_write) = std::os::unix::net::UnixStream::pair()?;
    let (output_write, output_read) = std::os::unix::net::UnixStream::pair()?;
    input_write.set_nonblocking(true)?;
    output_read.set_nonblocking(true)?;
    let input = Pipe::new(&input_read)?;
    let output = Pipe::new(&output_write)?;
    let mut producer = tokio::net::UnixStream::from_std(input_write)?;
    let mut consumer = tokio::net::UnixStream::from_std(output_read)?;
    let (local, mut peer) = tokio::net::UnixStream::pair()?;
    let worker = tokio::spawn(bridge_io(local, input, output));
    producer.write_all(b"request").await?;
    producer.shutdown().await?;
    let mut request = Vec::new();
    (&mut peer).take(32).read_to_end(&mut request).await?;
    assert_eq!(request, b"request");
    peer.write_all(b"response").await?;
    peer.shutdown().await?;
    let mut response = [0; 8];
    tokio::time::timeout(Duration::from_secs(2), consumer.read_exact(&mut response)).await??;
    assert_eq!(&response, b"response");
    tokio::time::timeout(Duration::from_secs(2), worker).await???;
    let (local, peer) = tokio::net::UnixStream::pair()?;
    let (held_input, _held_writer) = std::os::unix::net::UnixStream::pair()?;
    let worker = tokio::spawn(bridge_io(local, Pipe::new(&held_input)?, Pipe::new(&output_write)?));
    drop(peer);
    tokio::time::timeout(Duration::from_secs(2), worker).await???;
    Ok(())
}
