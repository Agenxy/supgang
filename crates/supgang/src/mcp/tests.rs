use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::Duration,
};

use rmcp::{
    ClientServiceExt, ServiceExt,
    model::{ClientInfo, ProtocolVersion},
    service::ClientLifecycleMode,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{SupgangMcp, transport::BoundedStdio};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn legacy_2025_lifecycle_lists_a_strict_read_only_surface() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let responses = exchange(
        directory.path(),
        &[
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "supgang-test", "version": "1"}
                }
            }),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        ],
    )
    .await?;

    let initialize = response_with_id(&responses, 1)?;
    assert_eq!(
        initialize.pointer("/result/protocolVersion"),
        Some(&json!("2025-11-25"))
    );
    assert!(initialize.pointer("/result/resultType").is_none());

    let list = response_with_id(&responses, 2)?;
    assert!(list.pointer("/result/resultType").is_none());
    assert!(list.pointer("/result/ttlMs").is_none());
    assert_tool_contract(list)?;
    Ok(())
}

#[tokio::test]
async fn modern_2026_discovery_is_self_contained_and_cacheable() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let responses = exchange(
        directory.path(),
        &[
            request_2026(1, "server/discover", &json!({})),
            request_2026(2, "tools/list", &json!({})),
        ],
    )
    .await?;

    let discover = response_with_id(&responses, 1)?;
    assert_eq!(discover.pointer("/result/resultType"), Some(&json!("complete")));
    assert_eq!(
        discover.pointer("/result/supportedVersions"),
        Some(&json!(["2026-07-28", "2025-11-25"]))
    );
    assert_eq!(discover.pointer("/result/cacheScope"), Some(&json!("public")));
    assert!(
        discover
            .pointer("/result/ttlMs")
            .and_then(Value::as_u64)
            .is_some_and(|ttl| ttl > 0)
    );

    let list = response_with_id(&responses, 2)?;
    assert_eq!(list.pointer("/result/resultType"), Some(&json!("complete")));
    assert_eq!(list.pointer("/result/cacheScope"), Some(&json!("public")));
    assert_tool_contract(list)?;
    Ok(())
}

#[tokio::test]
async fn official_sdk_clients_use_both_supported_protocol_eras() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;

    let (client_transport, server_transport) = tokio::io::duplex(super::transport::MAX_MCP_RESPONSE_BYTES * 4);
    let legacy_server = spawn_server(directory.path(), server_transport);
    let mut legacy_info = ClientInfo::default();
    legacy_info.protocol_version = ProtocolVersion::V_2025_11_25;
    let legacy = legacy_info.serve(client_transport).await?;
    assert_eq!(
        legacy.peer_info().map(|info| info.protocol_version.clone()),
        Some(ProtocolVersion::V_2025_11_25)
    );
    assert_eq!(
        tool_names(&legacy.list_tools(None).await?),
        ["fleet", "resolve", "status"]
    );
    legacy.cancel().await?;
    legacy_server.await??;

    let (client_transport, server_transport) = tokio::io::duplex(super::transport::MAX_MCP_RESPONSE_BYTES * 4);
    let modern_server = spawn_server(directory.path(), server_transport);
    let modern = ClientInfo::default()
        .serve_with_lifecycle(
            client_transport,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await?;
    assert_eq!(
        modern.peer_info().map(|info| info.protocol_version.clone()),
        Some(ProtocolVersion::V_2026_07_28)
    );
    assert_eq!(
        tool_names(&modern.list_tools(None).await?),
        ["fleet", "resolve", "status"]
    );
    modern.cancel().await?;
    modern_server.await??;
    Ok(())
}

#[tokio::test]
async fn tool_calls_are_strict_and_return_structured_local_state() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let local = crate::state::initialize(directory.path())?;
    let _name = crate::profile::load_or_create(directory.path(), local.identity().device.node_id())?;
    drop(local);
    let responses = exchange(
        directory.path(),
        &[
            request_2026(1, "tools/call", &json!({"name": "status", "arguments": {}})),
            request_2026(
                2,
                "tools/call",
                &json!({"name": "status", "arguments": {"write": true}}),
            ),
            request_2026(3, "tools/call", &json!({"name": "resolve", "arguments": {"peer": "x"}})),
        ],
    )
    .await?;

    let status = response_with_id(&responses, 1)?;
    assert_eq!(status.pointer("/result/isError"), Some(&json!(false)));
    assert_eq!(
        status.pointer("/result/structuredContent/schema"),
        Some(&json!("supgang.mcp.status/v1"))
    );
    assert_eq!(
        status.pointer("/result/structuredContent/service"),
        Some(&json!("stopped"))
    );
    assert_eq!(
        response_with_id(&responses, 2)?.pointer("/error/code"),
        Some(&json!(-32602))
    );
    assert_eq!(
        response_with_id(&responses, 3)?.pointer("/error/code"),
        Some(&json!(-32602))
    );
    Ok(())
}

#[tokio::test]
async fn offline_tools_never_create_or_repair_state() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let local = crate::state::initialize(directory.path())?;
    let _name = crate::profile::load_or_create(directory.path(), local.identity().device.node_id())?;
    drop(local);

    let journal_path = directory.path().join(crate::storage::JOURNAL_FILE_NAME);
    OpenOptions::new()
        .append(true)
        .open(&journal_path)?
        .write_all(&[0, 0])?;
    let before = fs::read(&journal_path)?;
    let peer_journal = directory.path().join(crate::peer_directory::PEER_DIRECTORY_FILE_NAME);
    assert!(!peer_journal.exists());

    let responses = exchange(
        directory.path(),
        &[
            request_2026(1, "tools/call", &json!({"name": "status", "arguments": {}})),
            request_2026(2, "tools/call", &json!({"name": "fleet", "arguments": {}})),
        ],
    )
    .await?;
    assert_eq!(
        response_with_id(&responses, 1)?.pointer("/result/isError"),
        Some(&json!(false))
    );
    assert_eq!(
        response_with_id(&responses, 2)?.pointer("/result/isError"),
        Some(&json!(false))
    );
    assert_eq!(fs::read(&journal_path)?, before);
    assert!(!peer_journal.exists());
    Ok(())
}

#[tokio::test]
async fn unsupported_protocol_and_oversized_input_fail_closed() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let unsupported = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "supgang-test", "version": "1"}
        }
    });
    let responses = exchange(
        directory.path(),
        &[
            unsupported,
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        ],
    )
    .await?;
    assert_eq!(
        response_with_id(&responses, 1)?.pointer("/result/protocolVersion"),
        Some(&json!("2025-11-25"))
    );

    let unsupported_modern = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2099-01-01",
                "io.modelcontextprotocol/clientInfo": {"name": "supgang-test", "version": "1"},
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    });
    let responses = exchange_tolerating_shutdown(directory.path(), &[unsupported_modern]).await?;
    assert_eq!(
        response_with_id(&responses, 2)?.pointer("/error/code"),
        Some(&json!(-32_022))
    );

    let missing_modern_metadata = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/list",
        "params": {
            "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
        }
    });
    let responses = exchange_tolerating_shutdown(directory.path(), &[missing_modern_metadata]).await?;
    assert_eq!(
        response_with_id(&responses, 3)?.pointer("/error/code"),
        Some(&json!(-32602))
    );

    let oversized = vec![b' '; super::transport::MAX_MCP_REQUEST_BYTES + 1];
    let raw = exchange_bytes(directory.path(), &oversized, true).await?;
    assert!(raw.is_empty());
    Ok(())
}

fn request_2026(id: u64, method: &str, parameters: &Value) -> Value {
    let mut parameters = parameters.as_object().cloned().unwrap_or_default();
    parameters.insert(
        "_meta".to_owned(),
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {"name": "supgang-test", "version": "1"},
            "io.modelcontextprotocol/clientCapabilities": {}
        }),
    );
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": parameters})
}

fn assert_tool_contract(response: &Value) -> Result<(), Box<dyn Error>> {
    let tools = response
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .ok_or("tools/list response has no tools")?;
    let names = tools
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(names, ["fleet", "resolve", "status"]);
    for tool in tools {
        assert_eq!(tool.pointer("/inputSchema/additionalProperties"), Some(&json!(false)));
        assert_eq!(tool.pointer("/outputSchema/additionalProperties"), Some(&json!(false)));
        assert_eq!(tool.pointer("/annotations/readOnlyHint"), Some(&json!(true)));
        assert_eq!(tool.pointer("/annotations/destructiveHint"), Some(&json!(false)));
        assert_eq!(tool.pointer("/annotations/idempotentHint"), Some(&json!(true)));
        assert_eq!(tool.pointer("/annotations/openWorldHint"), Some(&json!(false)));
    }
    Ok(())
}

fn response_with_id(responses: &[Value], id: u64) -> Result<&Value, Box<dyn Error>> {
    responses
        .iter()
        .find(|response| response.get("id").and_then(Value::as_u64) == Some(id))
        .ok_or_else(|| format!("MCP response {id} is missing").into())
}

fn tool_names(result: &rmcp::model::ListToolsResult) -> Vec<&str> {
    result.tools.iter().map(|tool| tool.name.as_ref()).collect()
}

fn spawn_server(
    state_directory: &Path,
    transport: tokio::io::DuplexStream,
) -> tokio::task::JoinHandle<Result<(), String>> {
    let owned_state_directory = state_directory.to_path_buf();
    tokio::spawn(async move {
        let (server_read, server_write) = tokio::io::split(transport);
        let running = SupgangMcp::new(owned_state_directory)
            .serve(BoundedStdio::new(server_read, server_write))
            .await
            .map_err(|error| error.to_string())?;
        running
            .waiting()
            .await
            .map(|_reason| ())
            .map_err(|error| error.to_string())
    })
}

async fn exchange(state_directory: &Path, requests: &[Value]) -> Result<Vec<Value>, Box<dyn Error>> {
    exchange_with_policy(state_directory, requests, false).await
}

async fn exchange_tolerating_shutdown(
    state_directory: &Path,
    requests: &[Value],
) -> Result<Vec<Value>, Box<dyn Error>> {
    exchange_with_policy(state_directory, requests, true).await
}

async fn exchange_with_policy(
    state_directory: &Path,
    requests: &[Value],
    tolerate_server_error: bool,
) -> Result<Vec<Value>, Box<dyn Error>> {
    let mut input = Vec::new();
    for request in requests {
        serde_json::to_writer(&mut input, request)?;
        input.push(b'\n');
    }
    let output = exchange_bytes(state_directory, &input, tolerate_server_error).await?;
    std::str::from_utf8(&output)?
        .lines()
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

async fn exchange_bytes(
    state_directory: &Path,
    input: &[u8],
    tolerate_server_error: bool,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let capacity = super::transport::MAX_MCP_RESPONSE_BYTES * 4;
    let (client, server) = tokio::io::duplex(capacity);
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (server_read, server_write) = tokio::io::split(server);
    let owned_state_directory = state_directory.to_path_buf();
    let server_task = tokio::spawn(async move {
        let running = SupgangMcp::new(owned_state_directory)
            .serve(BoundedStdio::new(server_read, server_write))
            .await
            .map_err(|error| error.to_string())?;
        running
            .waiting()
            .await
            .map(|_reason| ())
            .map_err(|error| error.to_string())
    });

    client_write.write_all(input).await?;
    client_write.shutdown().await?;
    let mut output = Vec::new();
    let (read_result, server_result) = tokio::time::timeout(TEST_TIMEOUT, async {
        tokio::join!(client_read.read_to_end(&mut output), server_task)
    })
    .await?;
    let _bytes_read = read_result?;
    let service_result = server_result?;
    if !tolerate_server_error {
        service_result?;
    }
    Ok(output)
}
