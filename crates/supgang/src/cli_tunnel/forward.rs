//! A loopback TCP listener on this computer whose connections each ride one
//! authenticated service stream to a named peer service, so a browser or any
//! TCP client reaches it as if it were local. Nothing listens beyond loopback.

use std::{
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use tokio::{net::TcpListener, sync::Semaphore};

use crate::{
    cli::{render_error, render_json},
    cli_control, control,
    ids::NodeId,
    record::ServiceName,
    transport, tunnel_policy,
};

/// Concurrent forwarded connections; more are closed at once rather than queued.
pub const MAX_FORWARDED_CONNECTIONS: usize = 32;

/// Parses a listen address that can only be a loopback socket. A bare port
/// listens on 127.0.0.1.
pub fn loopback_listen(text: &str) -> Result<SocketAddr, &'static str> {
    let address = text.parse::<u16>().map_or_else(
        |_| {
            text.parse::<SocketAddr>()
                .map_err(|_| "listen address must be a port or a loopback socket")
        },
        |port| Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
    )?;
    if !address.ip().is_loopback() {
        return Err("forward listens only on loopback (127.0.0.1 or [::1])");
    }
    if address.port() == 0 {
        return Err("listen port must be nonzero");
    }
    Ok(address)
}

/// Accepts connections until `shutdown` resolves, carrying each through one
/// service stream. A failed stream closes only that connection.
pub async fn serve(
    listener: TcpListener,
    directory: PathBuf,
    target: NodeId,
    name: [u8; 16],
    shutdown: impl std::future::Future<Output = ()>,
    report: impl Fn(&str) + Send + Sync + 'static,
) {
    let admission = Arc::new(Semaphore::new(MAX_FORWARDED_CONNECTIONS));
    let report = Arc::new(report);
    let mut connections = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        let accepted = tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => accepted,
            Some(_finished) = connections.join_next(), if !connections.is_empty() => continue,
        };
        let Ok((client, _)) = accepted else { continue };
        let Ok(permit) = Arc::clone(&admission).try_acquire_owned() else {
            report("forward is at its connection limit; a connection was closed");
            continue;
        };
        let directory = directory.clone();
        let report = Arc::clone(&report);
        connections.spawn(async move {
            let _permit = permit;
            let opened = tokio::task::spawn_blocking(move || control::connect_service(&directory, target, name)).await;
            let stream = match opened {
                Ok(Ok(stream)) => stream,
                Ok(Err(message)) => {
                    report(&message);
                    return;
                }
                Err(_) => return,
            };
            let Ok(()) = stream.set_nonblocking(true) else { return };
            let Ok(mut tunnel) = tokio::net::UnixStream::from_std(stream) else {
                return;
            };
            let mut client = client;
            let _closed = tokio::io::copy_bidirectional(&mut client, &mut tunnel).await;
        });
    }
    connections.shutdown().await;
}

pub fn forward(
    directory: &Path,
    listen: &str,
    peer: &str,
    service: &str,
    json: bool,
    output: &mut dyn Write,
    error: &mut dyn Write,
) -> ExitCode {
    let prepared = (|| {
        let address = loopback_listen(listen)?;
        let name = ServiceName::new(service).map_err(|_| "service name is invalid")?;
        let target = cli_control::resolve_peer_node(directory, peer)?;
        let runtime = transport::build_runtime().map_err(|_| "service transport runtime setup failed")?;
        let listener = runtime
            .block_on(TcpListener::bind(address))
            .map_err(|_| format!("could not listen on {address}; is the port already in use?"))?;
        Ok::<_, String>((address, name, target, runtime, listener))
    })();
    let (address, name, target, runtime, listener) = match prepared {
        Ok(prepared) => prepared,
        Err(message) => return render_error(json, &message, output, error),
    };
    let ready = if json {
        render_json(
            &serde_json::json!({
                "schema": "supgang.forward/v1",
                "status": "listening",
                "listen": address.to_string(),
                "peer": peer,
                "service": name.as_str(),
            }),
            output,
            error,
        )
    } else if writeln!(
        output,
        "Forwarding {address} to {peer} service {}. Press Ctrl-C to stop.",
        name.as_str()
    )
    .is_ok()
    {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    };
    if ready != ExitCode::SUCCESS {
        return ready;
    }
    let _flushed = output.flush();
    runtime.block_on(serve(
        listener,
        directory.to_path_buf(),
        target,
        tunnel_policy::encoded_name(&name),
        async {
            let _interrupted = tokio::signal::ctrl_c().await;
        },
        |message| {
            // Reasons are fixed service messages; no peer address is included.
            let _written = writeln!(std::io::stderr(), "supgang forward: {message}");
        },
    ));
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::loopback_listen;

    #[test]
    fn only_loopback_sockets_and_bare_ports_are_accepted() {
        assert_eq!(
            loopback_listen("14331").map(|a| a.to_string()),
            Ok("127.0.0.1:14331".to_owned())
        );
        assert_eq!(
            loopback_listen("127.0.0.1:8080").map(|a| a.to_string()),
            Ok("127.0.0.1:8080".to_owned())
        );
        assert_eq!(
            loopback_listen("[::1]:8080").map(|a| a.to_string()),
            Ok("[::1]:8080".to_owned())
        );
        for refused in [
            "0.0.0.0:8080",
            "192.168.1.5:80",
            "[::]:80",
            "localhost:80",
            "0",
            "127.0.0.1:0",
            "",
        ] {
            assert!(loopback_listen(refused).is_err(), "{refused}");
        }
    }
}
