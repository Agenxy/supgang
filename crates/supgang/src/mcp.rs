//! Read-only Model Context Protocol access to the local Supgang fleet.

use std::{
    borrow::Cow,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use rmcp::{
    ErrorData, RoleServer, ServerHandler, ServiceExt,
    handler::server::tool::schema_for_output,
    model::{
        CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, DiscoverResult,
        Implementation, JsonObject, ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities,
        ServerInfo, Tool, ToolAnnotations,
    },
    service::RequestContext,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    VERSION, cli_peer,
    control::{self, ControlReply, ControlRequest, ControlStatus},
    ids::NodeId,
    profile, state,
};

mod transport;

#[cfg(test)]
mod tests;

use transport::BoundedStdio;

const SUPPORTED_PROTOCOLS: &[ProtocolVersion] = &[ProtocolVersion::V_2026_07_28, ProtocolVersion::V_2025_11_25];
const TOOL_LIST_TTL_MS: u64 = 60 * 60 * 1_000;
const MAX_TOOL_VALUE_BYTES: usize = 96 * 1024;
const INSTRUCTIONS: &str = "Supgang is a local, read-only view of a sovereign computer fleet. Call fleet first. Address claims are device-signed but are not independent reachability proof; public means globally scoped, not necessarily reachable. Use resolve only when one computer needs every current candidate. Never describe a fresh record as online. No tool writes state, contacts a third party, or starts a network service. The MCP client controls where returned addresses are sent.";

/// MCP server startup or transport failure.
#[derive(Debug, Error)]
pub enum McpServeError {
    /// The current-thread asynchronous runtime could not be created.
    #[error("MCP runtime initialization failed")]
    Runtime,
    /// The stdio service could not start or ended with a transport failure.
    #[error("MCP stdio service failed")]
    Service,
}

/// Runs the bounded local MCP server until its client closes standard input.
///
/// # Errors
///
/// Returns a non-sensitive startup or transport classification.
pub fn serve_stdio(state_directory: PathBuf) -> Result<(), McpServeError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| McpServeError::Runtime)?;
    runtime.block_on(async move {
        let transport = BoundedStdio::new(tokio::io::stdin(), tokio::io::stdout());
        let running = SupgangMcp::new(state_directory)
            .serve(transport)
            .await
            .map_err(|_| McpServeError::Service)?;
        running
            .waiting()
            .await
            .map(|_reason| ())
            .map_err(|_| McpServeError::Service)
    })
}

#[derive(Clone, Debug)]
struct SupgangMcp {
    state_directory: Arc<PathBuf>,
}

impl SupgangMcp {
    fn new(state_directory: PathBuf) -> Self {
        Self {
            state_directory: Arc::new(state_directory),
        }
    }

    fn tools() -> Vec<Tool> {
        vec![
            Tool::new(
                "fleet",
                "List this computer and every known Supgang peer with complete signed local and public address candidates. Public scope does not prove reachability.",
                empty_input_schema(),
            )
            .with_title("Supgang fleet")
            .with_raw_output_schema(schema_for_output::<cli_peer::PeersOutput>())
            .with_annotations(read_annotations("Read Supgang fleet")),
            Tool::new(
                "resolve",
                "Resolve one computer name, shown fingerprint, or stable node ID to its complete fresh signed address candidate set.",
                resolve_input_schema(),
            )
            .with_title("Resolve Supgang computer")
            .with_raw_output_schema(schema_for_output::<cli_peer::ResolveOutput>())
            .with_annotations(read_annotations("Resolve Supgang computer")),
            Tool::new(
                "status",
                "Read this computer's Supgang identity, service state, and authenticated peer counts without changing state.",
                empty_input_schema(),
            )
            .with_title("Supgang status")
            .with_raw_output_schema(schema_for_output::<McpStatusOutput>())
            .with_annotations(read_annotations("Read Supgang status")),
        ]
    }

    fn call(&self, request: CallToolRequestParams) -> Result<CallToolResponse, ErrorData> {
        if request.input_responses.is_some() || request.request_state.is_some() {
            return Err(ErrorData::invalid_params(
                "Supgang read tools do not accept multi-round-trip state",
                None,
            ));
        }
        match request.name.as_ref() {
            "fleet" => {
                require_empty_arguments(request.arguments)?;
                match fleet_data(&self.state_directory) {
                    Ok(fleet) => structured_result(&fleet),
                    Err(message) => Ok(tool_failure(message)),
                }
            }
            "resolve" => {
                let arguments = parse_resolve_arguments(request.arguments)?;
                match resolve_data(&self.state_directory, &arguments.peer) {
                    Ok(resolution) => structured_result(&resolution),
                    Err(message) => Ok(tool_failure(message)),
                }
            }
            "status" => {
                require_empty_arguments(request.arguments)?;
                match status_data(&self.state_directory) {
                    Ok(status) => structured_result(&status),
                    Err(message) => Ok(tool_failure(message)),
                }
            }
            _ => Err(ErrorData::new(
                rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                "Unknown Supgang tool",
                None,
            )),
        }
    }
}

impl ServerHandler for SupgangMcp {
    fn get_info(&self) -> ServerInfo {
        let implementation = Implementation::new("org.agenxy.supgang", VERSION)
            .with_title("Supgang")
            .with_description("Sovereign peer address discovery")
            .with_website_url("https://agenxy.org/projects/supgang");
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
            .with_server_info(implementation)
            .with_instructions(INSTRUCTIONS)
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(SUPPORTED_PROTOCOLS)
    }

    async fn discover(&self, _context: RequestContext<RoleServer>) -> Result<DiscoverResult, ErrorData> {
        Ok(
            DiscoverResult::from_server_info(self.supported_protocol_versions().into_owned(), self.get_info())
                .with_ttl_ms(TOOL_LIST_TTL_MS)
                .with_cache_scope(CacheScope::Public),
        )
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        if request.is_some_and(|parameters| parameters.cursor.is_some()) {
            return Err(ErrorData::invalid_params("Supgang tools are not paginated", None));
        }
        let result = ListToolsResult::with_all_items(Self::tools());
        if is_modern(&context) {
            Ok(result
                .with_ttl_ms(TOOL_LIST_TTL_MS)
                .with_cache_scope(CacheScope::Public))
        } else {
            Ok(result)
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        self.call(request)
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        Self::tools().into_iter().find(|tool| tool.name == name)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveArguments {
    peer: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[schemars(deny_unknown_fields)]
struct McpStatusOutput {
    schema: &'static str,
    status: &'static str,
    version: &'static str,
    name: String,
    hive_id: String,
    node_id: String,
    service: &'static str,
    listen: Option<String>,
    active_peers: Option<usize>,
    known_peers: Option<usize>,
    member_count: usize,
    event_count: usize,
}

fn fleet_data(state_directory: &Path) -> Result<cli_peer::PeersOutput, String> {
    match control::request(state_directory, ControlRequest::Peers) {
        Ok(Some(ControlReply::Peers { value })) => Ok(value),
        Ok(Some(ControlReply::Error { message })) => Err(message),
        Ok(Some(_)) => Err("Supgang's local service returned an unexpected response".to_owned()),
        Ok(None) => cli_peer::peers_read_only(state_directory),
        Err(error) => Err(error.to_string()),
    }
}

fn status_data(state_directory: &Path) -> Result<McpStatusOutput, String> {
    match control::request(state_directory, ControlRequest::Status) {
        Ok(Some(ControlReply::Status { value })) => return Ok(running_status(value)),
        Ok(Some(ControlReply::Error { message })) => return Err(message),
        Ok(Some(_)) => return Err("Supgang's local service returned an unexpected response".to_owned()),
        Ok(None) => {}
        Err(error) => return Err(error.to_string()),
    }
    let local = state::open_read_only(state_directory).map_err(|error| error.to_string())?;
    let node_id = local.identity().device.node_id();
    let name = profile::load(state_directory).map_err(|error| error.to_string())?;
    Ok(McpStatusOutput {
        schema: "supgang.mcp.status/v1",
        status: "ok",
        version: VERSION,
        name: name.to_string(),
        hive_id: local.identity().hive_id.to_string(),
        node_id: node_id.to_string(),
        service: "stopped",
        listen: None,
        active_peers: None,
        known_peers: None,
        member_count: local.member_count(),
        event_count: local.event_count(),
    })
}

fn running_status(value: ControlStatus) -> McpStatusOutput {
    McpStatusOutput {
        schema: "supgang.mcp.status/v1",
        status: "ok",
        version: VERSION,
        name: value.name,
        hive_id: value.hive_id,
        node_id: value.node_id,
        service: "running",
        listen: Some(value.listen),
        active_peers: Some(value.active_peers),
        known_peers: Some(value.known_peers),
        member_count: value.member_count,
        event_count: value.event_count,
    }
}

fn resolve_data(state_directory: &Path, selector: &str) -> Result<cli_peer::ResolveOutput, String> {
    let node_id = if let Ok(node_id) = NodeId::from_str(selector) {
        node_id
    } else {
        let fleet = fleet_data(state_directory)?;
        cli_peer::resolve_selector_from_rows(&fleet.peers, selector)?
    };
    match control::request(state_directory, ControlRequest::Resolve(node_id)) {
        Ok(Some(ControlReply::Resolve { value })) => Ok(value),
        Ok(Some(ControlReply::Error { message })) => Err(message),
        Ok(Some(_)) => Err("Supgang's local service returned an unexpected response".to_owned()),
        Ok(None) => cli_peer::resolve_read_only(state_directory, &node_id.to_string()),
        Err(error) => Err(error.to_string()),
    }
}

fn structured_result<T: Serialize>(value: &T) -> Result<CallToolResponse, ErrorData> {
    let structured =
        serde_json::to_value(value).map_err(|_| ErrorData::internal_error("Supgang result encoding failed", None))?;
    let size = serde_json::to_vec(&structured)
        .map_err(|_| ErrorData::internal_error("Supgang result encoding failed", None))?
        .len();
    if size > MAX_TOOL_VALUE_BYTES {
        return Ok(tool_failure(
            "Supgang's result exceeds the MCP safety limit; inspect it with the local CLI",
        ));
    }
    Ok(CallToolResult::structured(structured).into())
}

fn tool_failure(message: impl Into<String>) -> CallToolResponse {
    CallToolResult::error(vec![ContentBlock::text(message.into())]).into()
}

fn require_empty_arguments(arguments: Option<JsonObject>) -> Result<(), ErrorData> {
    if arguments.is_none_or(|value| value.is_empty()) {
        Ok(())
    } else {
        Err(ErrorData::invalid_params("This tool accepts no arguments", None))
    }
}

fn parse_resolve_arguments(arguments: Option<JsonObject>) -> Result<ResolveArguments, ErrorData> {
    let arguments = arguments.ok_or_else(|| ErrorData::invalid_params("resolve requires peer", None))?;
    let parsed: ResolveArguments = serde_json::from_value(serde_json::Value::Object(arguments))
        .map_err(|_| ErrorData::invalid_params("resolve requires only a string peer", None))?;
    if !(2..=64).contains(&parsed.peer.len()) || !parsed.peer.is_ascii() {
        return Err(ErrorData::invalid_params(
            "peer must be 2 through 64 ASCII characters",
            None,
        ));
    }
    Ok(parsed)
}

fn empty_input_schema() -> Arc<JsonObject> {
    schema_object(serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {},
        "additionalProperties": false
    }))
}

fn resolve_input_schema() -> Arc<JsonObject> {
    schema_object(serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "peer": {
                "type": "string",
                "minLength": 2,
                "maxLength": 64,
                "pattern": "^[\\u0020-\\u007e]+$",
                "description": "Computer name, shown fingerprint, or stable node ID"
            }
        },
        "required": ["peer"],
        "additionalProperties": false
    }))
}

fn schema_object(value: serde_json::Value) -> Arc<JsonObject> {
    match value {
        serde_json::Value::Object(object) => Arc::new(object),
        _ => Arc::new(JsonObject::new()),
    }
}

fn read_annotations(title: &str) -> ToolAnnotations {
    ToolAnnotations::with_title(title)
        .read_only(true)
        .destructive(false)
        .idempotent(true)
        .open_world(false)
}

fn is_modern(context: &RequestContext<RoleServer>) -> bool {
    context
        .protocol_version()
        .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28)
}
