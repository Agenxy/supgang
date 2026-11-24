//! Minimal bounded JSON-RPC engine for Supgang's existing MCP surface.

use std::{
    io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{
    data,
    transport::{BoundedStdio, MAX_MCP_RESPONSE_BYTES},
};
use crate::VERSION;

const TOOLS: &str = include_str!("../../assets/mcp-tools.json");
const INITIALIZE_RESULT: &str = include_str!("../../assets/mcp-initialize-result.json");
const DISCOVER_RESULT: &str = include_str!("../../assets/mcp-discover-result.json");
const FIXTURE_VERSION: &str = "0.2.0-alpha.17";
pub(super) const MAX_TOOL_VALUE_BYTES: usize = 96 * 1024;
const MODERN_VERSION: &str = "2026-07-28";
const LEGACY_VERSION: &str = "2025-11-25";
const MISSING_META: &str = "request _meta is missing or has malformed required fields: io.modelcontextprotocol/protocolVersion, io.modelcontextprotocol/clientCapabilities";
const OVERSIZED_RESULT_MESSAGE: &str = "Supgang's result exceeds the MCP safety limit; inspect it with the local CLI";
const OVERSIZED_RESPONSE_MESSAGE: &str = "MCP response exceeds the fixed size limit";

#[derive(Debug)]
pub(super) struct RpcError {
    code: i32,
    message: &'static str,
    data: Option<Value>,
}

impl RpcError {
    const fn invalid_params(message: &'static str) -> Self {
        Self {
            code: -32602,
            message,
            data: None,
        }
    }
    const fn method_not_found(message: &'static str) -> Self {
        Self {
            code: -32601,
            message,
            data: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveArguments {
    peer: String,
}

struct Session<F> {
    legacy_initialized: bool,
    call_tool: F,
}

impl<F> Session<F>
where
    F: FnMut(Option<&Value>, bool) -> Result<String, RpcError>,
{
    const fn new(call_tool: F) -> Self {
        Self {
            legacy_initialized: false,
            call_tool,
        }
    }

    fn handle(&mut self, line: &[u8]) -> Option<Vec<u8>> {
        let value: Value = match serde_json::from_slice(line) {
            Ok(value) => value,
            Err(_) => return Some(error_response(Some(&Value::Null), -32700, "Parse error", None)),
        };
        let Some(object) = value.as_object() else {
            return Some(error_response(None, -32600, "Invalid request", None));
        };
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(bound_response(
                error_response(object.get("id"), -32600, "Invalid request", None),
                object.get("id"),
                None,
            ));
        }
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return Some(bound_response(
                error_response(object.get("id"), -32600, "Invalid request", None),
                object.get("id"),
                None,
            ));
        };
        if method == "notifications/initialized" {
            return None;
        }
        let id = object.get("id")?;
        let params = object.get("params");
        let (reply, tool_failure_mode) = self.dispatch(method, id, params);
        Some(bound_response(reply, Some(id), tool_failure_mode))
    }

    fn dispatch(&mut self, method: &str, id: &Value, params: Option<&Value>) -> (Vec<u8>, Option<bool>) {
        let mut tool_modern = None;
        let outcome = match method {
            "ping" => Ok("{}".to_owned()),
            "initialize" => self.initialize(params),
            _ => {
                let modern = match self.request_mode(params) {
                    Ok(modern) => modern,
                    Err(problem) => return (problem.into_response(id), None),
                };
                match method {
                    "server/discover" if modern => Ok(template(DISCOVER_RESULT)),
                    "tools/list" => list_tools(params, modern),
                    "tools/call" => {
                        tool_modern = Some(modern);
                        (self.call_tool)(params, modern)
                    }
                    _ => Err(RpcError::method_not_found("Method not found")),
                }
            }
        };
        match outcome {
            Ok(result) => (success_response(id, &result), tool_modern),
            Err(problem) => (problem.into_response(id), None),
        }
    }

    fn initialize(&mut self, params: Option<&Value>) -> Result<String, RpcError> {
        let requested = params
            .and_then(|value| value.get("protocolVersion"))
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params("Invalid initialize request"))?;
        if requested != LEGACY_VERSION {
            return Err(RpcError {
                code: -32022,
                message: "Unsupported protocol version",
                data: Some(json!({"requested": requested, "supported": [LEGACY_VERSION]})),
            });
        }
        self.legacy_initialized = true;
        Ok(template(INITIALIZE_RESULT))
    }

    fn request_mode(&self, params: Option<&Value>) -> Result<bool, RpcError> {
        let metadata = params.and_then(|value| value.get("_meta"));
        let version = metadata
            .and_then(|value| value.get("io.modelcontextprotocol/protocolVersion"))
            .and_then(Value::as_str);
        if let Some(version) = version {
            if version == MODERN_VERSION {
                if !metadata
                    .and_then(|value| value.get("io.modelcontextprotocol/clientCapabilities"))
                    .is_some_and(Value::is_object)
                {
                    return Err(RpcError::invalid_params(
                        "2026-07-28 requests require clientCapabilities metadata",
                    ));
                }
                return Ok(true);
            }
            if version != LEGACY_VERSION {
                return Err(RpcError {
                    code: -32022,
                    message: "Unsupported protocol version",
                    data: Some(json!({"requested": version, "supported": [MODERN_VERSION, LEGACY_VERSION]})),
                });
            }
        }
        if self.legacy_initialized {
            Ok(false)
        } else {
            Err(RpcError::invalid_params(MISSING_META))
        }
    }
}

impl RpcError {
    fn into_response(self, id: &Value) -> Vec<u8> {
        error_response(Some(id), self.code, self.message, self.data.as_ref())
    }
}

fn template(source: &str) -> String {
    source.trim_end().replace(
        &Value::String(FIXTURE_VERSION.to_owned()).to_string(),
        &Value::String(VERSION.to_owned()).to_string(),
    )
}

fn list_tools(params: Option<&Value>, modern: bool) -> Result<String, RpcError> {
    if params
        .and_then(|value| value.get("cursor"))
        .is_some_and(|value| !value.is_null())
    {
        return Err(RpcError::invalid_params("Supgang tools are not paginated"));
    }
    let tools = TOOLS.trim_end();
    if modern {
        Ok(format!(
            "{{\"resultType\":\"complete\",\"ttlMs\":3600000,\"cacheScope\":\"public\",\"tools\":{tools}}}"
        ))
    } else {
        Ok(format!("{{\"tools\":{tools}}}"))
    }
}

fn call_tool(state: &Path, params: Option<&Value>, modern: bool) -> Result<String, RpcError> {
    let params = params
        .and_then(Value::as_object)
        .ok_or_else(|| RpcError::invalid_params("Invalid tool call"))?;
    if params.get("inputResponses").is_some_and(|value| !value.is_null())
        || params.get("requestState").is_some_and(|value| !value.is_null())
    {
        return Err(RpcError::invalid_params(
            "Supgang read tools do not accept multi-round-trip state",
        ));
    }
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("Invalid tool call"))?;
    let arguments = params.get("arguments").filter(|value| !value.is_null());
    match name {
        "fleet" => {
            require_empty_arguments(arguments)?;
            match data::fleet_data(state) {
                Ok(value) => structured_result(&value, modern),
                Err(message) => Ok(tool_failure(&message, modern)),
            }
        }
        "status" => {
            require_empty_arguments(arguments)?;
            match data::status_data(state) {
                Ok(value) => structured_result(&value, modern),
                Err(message) => Ok(tool_failure(&message, modern)),
            }
        }
        "resolve" => {
            let peer = parse_resolve_arguments(arguments)?;
            match data::resolve_data(state, &peer) {
                Ok(value) => structured_result(&value, modern),
                Err(message) => Ok(tool_failure(&message, modern)),
            }
        }
        _ => Err(RpcError::method_not_found("Unknown Supgang tool")),
    }
}

fn require_empty_arguments(arguments: Option<&Value>) -> Result<(), RpcError> {
    if arguments.is_none_or(|value| value.as_object().is_some_and(serde_json::Map::is_empty)) {
        Ok(())
    } else {
        Err(RpcError::invalid_params("This tool accepts no arguments"))
    }
}

fn parse_resolve_arguments(arguments: Option<&Value>) -> Result<String, RpcError> {
    let arguments = arguments.ok_or_else(|| RpcError::invalid_params("resolve requires peer"))?;
    let parsed: ResolveArguments = serde_json::from_value(arguments.clone())
        .map_err(|_| RpcError::invalid_params("resolve requires only a string peer"))?;
    if !(2..=64).contains(&parsed.peer.len()) || !parsed.peer.is_ascii() {
        return Err(RpcError::invalid_params("peer must be 2 through 64 ASCII characters"));
    }
    Ok(parsed.peer)
}

pub(super) fn structured_result<T: Serialize>(value: &T, modern: bool) -> Result<String, RpcError> {
    let structured = serde_json::to_value(value).map_err(|_| RpcError {
        code: -32603,
        message: "Supgang result encoding failed",
        data: None,
    })?;
    let encoded = structured.to_string();
    if encoded.len() > MAX_TOOL_VALUE_BYTES {
        return Ok(tool_failure(OVERSIZED_RESULT_MESSAGE, modern));
    }
    let text = Value::String(encoded.clone());
    let prefix = if modern { "\"resultType\":\"complete\"," } else { "" };
    Ok(format!(
        "{{{prefix}\"content\":[{{\"type\":\"text\",\"text\":{text}}}],\"structuredContent\":{encoded},\"isError\":false}}"
    ))
}

fn tool_failure(message: &str, modern: bool) -> String {
    let text = Value::String(message.to_owned());
    let prefix = if modern { "\"resultType\":\"complete\"," } else { "" };
    format!("{{{prefix}\"content\":[{{\"type\":\"text\",\"text\":{text}}}],\"isError\":true}}")
}

pub(super) fn bound_response(reply: Vec<u8>, id: Option<&Value>, tool_failure_mode: Option<bool>) -> Vec<u8> {
    if reply.len() <= MAX_MCP_RESPONSE_BYTES {
        return reply;
    }
    if let (Some(id), Some(modern)) = (id, tool_failure_mode) {
        let fallback = success_response(id, &tool_failure(OVERSIZED_RESULT_MESSAGE, modern));
        if fallback.len() <= MAX_MCP_RESPONSE_BYTES {
            return fallback;
        }
    }
    let fallback = error_response(id, -32603, OVERSIZED_RESPONSE_MESSAGE, None);
    if fallback.len() <= MAX_MCP_RESPONSE_BYTES {
        return fallback;
    }
    error_response(None, -32603, OVERSIZED_RESPONSE_MESSAGE, None)
}

fn success_response(id: &Value, result: &str) -> Vec<u8> {
    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{result}}}").into_bytes()
}

fn error_response(id: Option<&Value>, code: i32, message: &str, data: Option<&Value>) -> Vec<u8> {
    let id = id.map_or_else(String::new, |value| format!(",\"id\":{value}"));
    let message = Value::String(message.to_owned());
    let data = data.map_or_else(String::new, |value| format!(",\"data\":{value}"));
    format!("{{\"jsonrpc\":\"2.0\"{id},\"error\":{{\"code\":{code},\"message\":{message}{data}}}}}").into_bytes()
}

/// Serves a bounded stream until EOF or a fatal transport error.
///
/// # Errors
/// Returns a transport error when the stream cannot be safely read or written.
pub(super) async fn serve<R, W>(state_directory: PathBuf, transport: BoundedStdio<R, W>) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    serve_with(transport, move |params, modern| {
        call_tool(&state_directory, params, modern)
    })
    .await
}

pub(super) async fn serve_with<R, W, F>(mut transport: BoundedStdio<R, W>, call_tool: F) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut(Option<&Value>, bool) -> Result<String, RpcError>,
{
    let mut session = Session::new(call_tool);
    while let Some(line) = transport.read_line().await? {
        if let Some(reply) = session.handle(&line) {
            transport.write_line(&reply).await?;
        }
    }
    Ok(())
}
