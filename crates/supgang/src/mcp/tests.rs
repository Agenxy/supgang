use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::Duration,
};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{protocol, transport::BoundedStdio};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn mcp_2026_versioning_and_compatibility_initialize_selects_only_legacy() -> Result<(), Box<dyn Error>> {
    // MCP 2026-07-28, Versioning and Compatibility:
    // "Backward Compatibility with Initialization-Based Versions" makes initialize
    // the legacy door. UnsupportedProtocolVersionError lists that door's versions.
    let directory = crate::storage::test_tempdir()?;
    for requested in ["2026-07-28", "2099-01-01"] {
        for metadata in [
            None,
            Some(json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28"})),
        ] {
            let mut request = initialize_request(requested);
            if let Some(metadata) = metadata {
                request
                    .get_mut("params")
                    .and_then(Value::as_object_mut)
                    .ok_or("initialize params must be an object")?
                    .insert("_meta".to_owned(), metadata);
            }
            let responses = exchange_tolerating_shutdown(directory.path(), &[request]).await?;
            let response = response_with_id(&responses, 1)?;
            assert_eq!(
                response.get("error"),
                Some(&json!({
                    "code": -32022,
                    "message": "Unsupported protocol version",
                    "data": {"requested": requested, "supported": ["2025-11-25"]}
                }))
            );
            assert!(response.get("result").is_none());
        }
    }
    Ok(())
}

#[tokio::test]
async fn legacy_initialize_is_not_subject_to_modern_metadata_requirements() -> Result<(), Box<dyn Error>> {
    let directory = crate::storage::test_tempdir()?;
    let mut request = initialize_request("2025-11-25");
    request
        .get_mut("params")
        .and_then(Value::as_object_mut)
        .ok_or("initialize params must be an object")?
        .insert(
            "_meta".to_owned(),
            json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28"}),
        );
    let responses = exchange(
        directory.path(),
        &[
            request,
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        ],
    )
    .await?;
    assert_eq!(
        response_with_id(&responses, 1)?.pointer("/result/protocolVersion"),
        Some(&json!("2025-11-25"))
    );
    let list = response_with_id(&responses, 2)?;
    assert!(list.pointer("/result/resultType").is_none());
    assert!(list.pointer("/result/ttlMs").is_none());
    assert_tool_contract(list)?;
    Ok(())
}

#[tokio::test]
async fn legacy_2025_lifecycle_lists_a_strict_read_only_surface() -> Result<(), Box<dyn Error>> {
    let directory = crate::storage::test_tempdir()?;
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
    let directory = crate::storage::test_tempdir()?;
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
async fn official_sdk_client_transcript_replays_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let transcript = include_str!("../../assets/mcp-sdk-client.ndjson");
    let lines: Vec<&str> = transcript.lines().collect();
    assert_eq!(lines.len(), 9);
    let directory = crate::storage::test_tempdir()?;
    for session in [
        lines.get(..5).ok_or("missing legacy transcript")?,
        lines.get(5..).ok_or("missing modern transcript")?,
    ] {
        let mut input = Vec::new();
        let mut expected = Vec::new();
        for line in session {
            if let Some(message) = line.strip_prefix("C:") {
                input.extend_from_slice(message.as_bytes());
                input.push(b'\n');
            } else if let Some(message) = line.strip_prefix("S:") {
                expected.extend_from_slice(message.as_bytes());
                expected.push(b'\n');
            } else {
                return Err("invalid captured MCP direction".into());
            }
        }
        assert_eq!(exchange_bytes(directory.path(), &input, false).await?, expected);
    }
    Ok(())
}

#[tokio::test]
async fn captured_resolve_error_replays_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let transcript = include_str!("../../assets/mcp-resolve-call.ndjson");
    let mut lines = transcript.lines();
    let request = lines
        .next()
        .and_then(|line| line.strip_prefix("C:"))
        .ok_or("missing captured request")?;
    let reply = lines
        .next()
        .and_then(|line| line.strip_prefix("S:"))
        .ok_or("missing captured reply")?;
    assert!(lines.next().is_none());

    let directory = crate::storage::test_tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let local = crate::state::initialize(directory.path())?;
    let _name = crate::profile::load_or_create(directory.path(), local.identity().device.node_id())?;
    drop(local);

    let actual = exchange_bytes(directory.path(), format!("{request}\n").as_bytes(), false).await?;
    assert_eq!(actual, format!("{reply}\n").as_bytes());
    Ok(())
}

#[tokio::test]
async fn malformed_and_unknown_requests_have_bounded_json_rpc_errors() -> Result<(), Box<dyn Error>> {
    let directory = crate::storage::test_tempdir()?;
    let input = b"{\n[]\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n";
    let output = exchange_bytes(directory.path(), input, false).await?;
    let lines = std::str::from_utf8(&output)?.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 3);
    assert_eq!(
        serde_json::from_str::<Value>(lines.first().ok_or("missing parse error")?)?,
        json!({
            "jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "Parse error"}
        })
    );
    assert_eq!(
        serde_json::from_str::<Value>(lines.get(1).ok_or("missing invalid request")?)?,
        json!({
            "jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid request"}
        })
    );
    assert_eq!(
        lines.get(2).copied(),
        Some("{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{}}")
    );

    let unknown = request_2026(4, "server/no-such-method", &json!({}));
    let responses = exchange(directory.path(), &[unknown]).await?;
    assert_eq!(
        response_with_id(&responses, 4)?.pointer("/error/code"),
        Some(&json!(-32601))
    );
    Ok(())
}

#[tokio::test]
async fn modern_tool_calls_without_initialize_are_strict_and_return_structured_local_state()
-> Result<(), Box<dyn Error>> {
    let directory = crate::storage::test_tempdir()?;
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
        Some(&json!("supgang.mcp.status/v2"))
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
    let directory = crate::storage::test_tempdir()?;
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
    let directory = crate::storage::test_tempdir()?;
    let responses = exchange_tolerating_shutdown(directory.path(), &[initialize_request("2025-06-18")]).await?;
    let unsupported = response_with_id(&responses, 1)?;
    assert_eq!(unsupported.pointer("/error/code"), Some(&json!(-32022)));
    assert_eq!(
        unsupported.pointer("/error/data"),
        Some(&json!({"requested": "2025-06-18", "supported": ["2025-11-25"]}))
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
    assert!(raw.is_empty(), "{raw:?}");
    Ok(())
}

#[tokio::test]
async fn quote_dense_near_cap_tool_reply_returns_bounded_error_and_keeps_session_open() -> Result<(), Box<dyn Error>> {
    assert_eq!(super::transport::MAX_MCP_REQUEST_BYTES, 16 * 1024);
    assert_eq!(protocol::MAX_TOOL_VALUE_BYTES, 96 * 1024);
    assert_eq!(super::transport::MAX_MCP_RESPONSE_BYTES, 256 * 1024);

    let payload = json!({"value": "\"".repeat(49_000)});
    let encoded_len = payload.to_string().len();
    assert!(
        encoded_len <= protocol::MAX_TOOL_VALUE_BYTES,
        "encoded_len={encoded_len}"
    );
    assert!(
        encoded_len > protocol::MAX_TOOL_VALUE_BYTES - 4 * 1024,
        "encoded_len={encoded_len}"
    );
    let raw_structured = protocol::structured_result(&payload, true).map_err(|error| format!("{error:?}"))?;
    assert!(
        raw_structured.len() > super::transport::MAX_MCP_RESPONSE_BYTES,
        "raw_structured.len()={}",
        raw_structured.len()
    );

    let modern_requests = [
        request_2026(1, "tools/call", &json!({"name": "fleet", "arguments": {}})),
        json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
        request_2026(3, "tools/list", &json!({})),
    ];
    let modern_payload = payload.clone();
    let modern_responses = exchange_with_tool_caller(&modern_requests, move |_params, modern| {
        protocol::structured_result(&modern_payload, modern)
    })
    .await?;
    let modern_call = response_with_id(&modern_responses, 1)?;
    assert_eq!(modern_call.pointer("/result/isError"), Some(&json!(true)));
    assert_eq!(modern_call.pointer("/result/resultType"), Some(&json!("complete")));
    assert!(modern_call.pointer("/result/structuredContent").is_none());
    assert!(
        modern_call
            .pointer("/result/content/0/text")
            .and_then(Value::as_str)
            .is_some_and(|text| text.contains("safety limit"))
    );
    assert_eq!(response_with_id(&modern_responses, 2)?.get("result"), Some(&json!({})));
    assert_tool_contract(response_with_id(&modern_responses, 3)?)?;

    let legacy_requests = [
        initialize_request("2025-11-25"),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "fleet", "arguments": {}}}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}),
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}}),
    ];
    let legacy_responses = exchange_with_tool_caller(&legacy_requests, move |_params, modern| {
        protocol::structured_result(&payload, modern)
    })
    .await?;
    let legacy_call = response_with_id(&legacy_responses, 2)?;
    assert_eq!(legacy_call.pointer("/result/isError"), Some(&json!(true)));
    assert!(legacy_call.pointer("/result/resultType").is_none());
    assert!(legacy_call.pointer("/result/structuredContent").is_none());
    assert_eq!(response_with_id(&legacy_responses, 3)?.get("result"), Some(&json!({})));
    assert_tool_contract(response_with_id(&legacy_responses, 4)?)?;
    Ok(())
}

#[tokio::test]
async fn response_pushed_over_cap_by_request_id_stays_bounded_and_open() -> Result<(), Box<dyn Error>> {
    // Choose a quote-dense value whose structured_result alone stays just under 256 KiB,
    // then pair it with a large valid request id (< 16 KiB request cap) so only the full
    // JSON-RPC envelope exceeds MAX_MCP_RESPONSE_BYTES.
    let payload = json!({"value": "\"".repeat(42_500)});
    let encoded_len = payload.to_string().len();
    assert!(
        encoded_len <= protocol::MAX_TOOL_VALUE_BYTES,
        "encoded_len={encoded_len}"
    );
    let raw_structured = protocol::structured_result(&payload, true).map_err(|error| format!("{error:?}"))?;
    assert!(
        raw_structured.len() <= super::transport::MAX_MCP_RESPONSE_BYTES,
        "raw_structured.len()={}",
        raw_structured.len()
    );
    let large_id = "r".repeat(12 * 1024);
    assert!(
        raw_structured.len() + large_id.len() > super::transport::MAX_MCP_RESPONSE_BYTES,
        "combined envelope must exceed transport cap"
    );

    let mut call = request_2026(1, "tools/call", &json!({"name": "fleet", "arguments": {}}));
    call.as_object_mut()
        .ok_or("request must be an object")?
        .insert("id".to_owned(), Value::String(large_id.clone()));
    let requests = [call, json!({"jsonrpc": "2.0", "id": 2, "method": "ping"})];
    let responses = exchange_with_tool_caller(&requests, move |_params, modern| {
        protocol::structured_result(&payload, modern)
    })
    .await?;

    let first = responses
        .iter()
        .find(|response| response.get("id").and_then(Value::as_str) == Some(large_id.as_str()))
        .ok_or("missing bounded reply for large request id")?;
    assert_eq!(first.pointer("/result/isError"), Some(&json!(true)));
    assert!(first.pointer("/result/structuredContent").is_none());
    assert_eq!(response_with_id(&responses, 2)?.get("result"), Some(&json!({})));
    Ok(())
}

#[test]
fn oversized_non_tool_response_falls_back_to_bounded_internal_error() -> Result<(), Box<dyn Error>> {
    let oversized = vec![b'x'; super::transport::MAX_MCP_RESPONSE_BYTES + 1];
    let normal_id = json!(7);
    let reply = protocol::bound_response(oversized.clone(), Some(&normal_id), None);
    assert!(reply.len() <= super::transport::MAX_MCP_RESPONSE_BYTES);
    let parsed: Value = serde_json::from_slice(&reply)?;
    assert_eq!(parsed.get("id"), Some(&normal_id));
    assert_eq!(parsed.pointer("/error/code"), Some(&json!(-32603)));

    let huge_id = Value::String("i".repeat(super::transport::MAX_MCP_RESPONSE_BYTES));
    let stripped = protocol::bound_response(oversized, Some(&huge_id), Some(true));
    assert!(stripped.len() <= super::transport::MAX_MCP_RESPONSE_BYTES);
    let parsed_stripped: Value = serde_json::from_slice(&stripped)?;
    assert!(parsed_stripped.get("id").is_none());
    assert_eq!(parsed_stripped.pointer("/error/code"), Some(&json!(-32603)));
    Ok(())
}

fn initialize_request(version: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {"name": "supgang-test", "version": "1"}
        }
    })
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
        protocol::serve(owned_state_directory, BoundedStdio::new(server_read, server_write))
            .await
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

async fn exchange_with_tool_caller<F>(requests: &[Value], call_tool: F) -> Result<Vec<Value>, Box<dyn Error>>
where
    F: FnMut(Option<&Value>, bool) -> Result<String, protocol::RpcError> + Send + 'static,
{
    let mut input = Vec::new();
    for request in requests {
        serde_json::to_writer(&mut input, request)?;
        input.push(b'\n');
    }
    let capacity = super::transport::MAX_MCP_RESPONSE_BYTES * 4;
    let (client, server) = tokio::io::duplex(capacity);
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (server_read, server_write) = tokio::io::split(server);
    let server_task = tokio::spawn(async move {
        protocol::serve_with(BoundedStdio::new(server_read, server_write), call_tool)
            .await
            .map_err(|error| error.to_string())
    });

    client_write.write_all(&input).await?;
    client_write.shutdown().await?;
    let mut output = Vec::new();
    let (read_result, server_result) = tokio::time::timeout(TEST_TIMEOUT, async {
        tokio::join!(client_read.read_to_end(&mut output), server_task)
    })
    .await?;
    let _bytes_read = read_result?;
    server_result??;
    let text = std::str::from_utf8(&output)?;
    let mut responses = Vec::new();
    for line in text.lines() {
        assert!(
            line.len() <= super::transport::MAX_MCP_RESPONSE_BYTES,
            "wire response line exceeded cap: {}",
            line.len()
        );
        responses.push(serde_json::from_str(line)?);
    }
    Ok(responses)
}
