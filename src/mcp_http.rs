//! MCP-over-HTTP Server for narsil-mcp
//!
//! Implements the MCP Streamable HTTP Transport (2024-11-05),
//! allowing LLM agents and remote clients to use narsil-mcp
//! via HTTP instead of stdio.
//!
//! Key design:
//! - `POST /message` — MCP JSON-RPC over HTTP (Streamable HTTP spec)
//! - `GET /health` — health check
//! - `X-Session-Id` header — session management per client
//! - Multi-client concurrent support via axum async handlers
//! - Reuses McpServer's engine + tool_registry + config

use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::config::schema::ToolConfig;
use crate::config::{ClientInfo, ConfigLoader};
use crate::index::CodeIntelEngine;
use crate::tool_handlers::ToolRegistry;
use crate::tool_metadata::TOOL_METADATA;

/// MCP Protocol Version
const MCP_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "narsil-mcp";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum HTTP request body size (10 MB).
const MAX_HTTP_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Per-session state for multi-client support
#[derive(Debug, Clone)]
struct SessionState {
    client_info: Option<ClientInfo>,
    initialized: bool,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            client_info: None,
            initialized: false,
        }
    }
}

/// MCP-over-HTTP Server
pub struct McpHttpServer {
    engine: Arc<CodeIntelEngine>,
    tool_registry: ToolRegistry,
    config: ToolConfig,
    port: u16,
}

/// Shared application state for axum handlers
#[derive(Clone)]
struct McpHttpState {
    engine: Arc<CodeIntelEngine>,
    tool_registry: Arc<ToolRegistry>,
    config: ToolConfig,
    sessions: Arc<DashMap<String, SessionState>>,
}

impl McpHttpServer {
    /// Create a new MCP-over-HTTP server
    pub fn new(engine: Arc<CodeIntelEngine>, port: u16) -> Self {
        let config = ConfigLoader::new().load().unwrap_or_else(|e| {
            warn!("Failed to load config: {}. Using defaults.", e);
            ConfigLoader::new().default_config
        });

        Self {
            engine,
            tool_registry: ToolRegistry::new(),
            config,
            port,
        }
    }

    /// Run the MCP-over-HTTP server (blocking)
    pub async fn run(self) -> Result<()> {
        let state = McpHttpState {
            engine: self.engine,
            tool_registry: Arc::new(self.tool_registry),
            config: self.config,
            sessions: Arc::new(DashMap::new()),
        };

        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        let app = Router::new()
            .route("/health", get(health))
            .route("/message", post(handle_message))
            .layer(cors)
            .layer(axum::extract::DefaultBodyLimit::max(MAX_HTTP_BODY_SIZE))
            .with_state(state);

        let addr = format!("0.0.0.0:{}", self.port);
        info!("MCP-over-HTTP server starting on http://{}", addr);
        info!(
            "Endpoint: POST http://{}:{}/message",
            "localhost", self.port
        );

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}

// ── GET /health ──────────────────────────────────────────────────────────────

/// Health check endpoint
async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": SERVER_NAME,
        "version": SERVER_VERSION,
        "protocol": MCP_VERSION,
    }))
}

// ── Session management ───────────────────────────────────────────────────────

/// Extract or generate a session ID from the request headers
fn get_or_create_session_id(
    headers: &HeaderMap,
    sessions: &DashMap<String, SessionState>,
) -> String {
    if let Some(session_id) = headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
    {
        if !sessions.contains_key(session_id) {
            sessions.insert(session_id.to_string(), SessionState::default());
        }
        session_id.to_string()
    } else {
        let session_id = Uuid::new_v4().to_string();
        sessions.insert(session_id.clone(), SessionState::default());
        session_id
    }
}

// ── POST /message ────────────────────────────────────────────────────────────

/// Main MCP message handler — dispatches JSON-RPC methods
async fn handle_message(
    State(state): State<McpHttpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let session_id = get_or_create_session_id(&headers, &state.sessions);

    let method = body
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let id = body.get("id").cloned();
    let params = body.get("params").cloned().unwrap_or(json!({}));

    debug!(
        "MCP HTTP [{}] method={} id={:?}",
        session_id, method, id
    );

    let response = match method {
        "initialize" => handle_initialize(&state, &session_id, id, params),
        "initialized" => {
            if let Some(mut session) = state.sessions.get_mut(&session_id) {
                session.initialized = true;
            }
            jsonrpc_success(id, json!({}))
        }
        "tools/list" => handle_tools_list(&state, id),
        "tools/call" => handle_tool_call(&state, id, params).await,
        "resources/list" => jsonrpc_success(id, json!({"resources": []})),
        "resources/read" => handle_resource_read(&state, id, params).await,
        "prompts/list" => handle_prompts_list(id),
        "prompts/get" => handle_prompts_get(id, params),
        _ => jsonrpc_error(id, -32601, &format!("Method not found: {method}")),
    };

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        "x-session-id",
        session_id.parse().unwrap(),
    );
    response_headers.insert(
        "content-type",
        "application/json".parse().unwrap(),
    );

    (response_headers, Json(response))
}

// ── Handler implementations ──────────────────────────────────────────────────

fn handle_initialize(
    state: &McpHttpState,
    session_id: &str,
    id: Option<Value>,
    params: Value,
) -> JsonRpcResponse {
    if let Some(client_info) = params.get("clientInfo") {
        if let (Some(name), version) = (
            client_info.get("name").and_then(|v| v.as_str()),
            client_info
                .get("version")
                .and_then(|v| v.as_str())
                .map(String::from),
        ) {
            let client = ClientInfo {
                name: name.to_string(),
                version,
            };
            info!("Client [{}]: {} {:?}", session_id, client.name, client.version);
            if let Some(mut session) = state.sessions.get_mut(session_id) {
                session.client_info = Some(client);
                session.initialized = true;
            }
        }
    }

    jsonrpc_success(
        id,
        json!({
            "protocolVersion": MCP_VERSION,
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION
            },
            "capabilities": {
                "tools": {},
                "resources": {
                    "subscribe": false,
                    "listChanged": false
                },
                "prompts": {}
            }
        }),
    )
}

fn handle_tools_list(_state: &McpHttpState, id: Option<Value>) -> JsonRpcResponse {
    let tools: Vec<Value> = TOOL_METADATA
        .iter()
        .map(|(_name, meta)| {
            json!({
                "name": meta.name,
                "description": meta.description,
                "inputSchema": meta.input_schema,
            })
        })
        .collect();

    info!("Returning {} tools via HTTP", tools.len());
    jsonrpc_success(id, json!({"tools": tools}))
}

async fn handle_tool_call(
    state: &McpHttpState,
    id: Option<Value>,
    params: Value,
) -> JsonRpcResponse {
    let start = std::time::Instant::now();
    let tool_name = params
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(json!({}));

    debug!("Tool call via HTTP: {tool_name}");

    let result = state
        .tool_registry
        .dispatch(tool_name, &state.engine, arguments)
        .await;

    let elapsed = start.elapsed();
    info!(
        "Tool '{tool_name}' HTTP: {}ms success={}",
        elapsed.as_millis(),
        result.is_ok()
    );

    match result {
        Ok(content) => jsonrpc_success(
            id,
            json!({
                "content": [{"type": "text", "text": content}]
            }),
        ),
        Err(e) => jsonrpc_error(id, -32000, &e.to_string()),
    }
}

async fn handle_resource_read(
    state: &McpHttpState,
    id: Option<Value>,
    params: Value,
) -> JsonRpcResponse {
    let uri = params
        .get("uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match state.engine.read_resource(uri).await {
        Ok(content) => jsonrpc_success(
            id,
            json!({
                "contents": [{"uri": uri, "mimeType": "text/plain", "text": content}]
            }),
        ),
        Err(e) => jsonrpc_error(id, -32000, &e.to_string()),
    }
}

fn handle_prompts_list(id: Option<Value>) -> JsonRpcResponse {
    jsonrpc_success(
        id,
        json!({
            "prompts": [
                {
                    "name": "explain_codebase",
                    "description": "Get an overview of a codebase's architecture and key components",
                    "arguments": [
                        {"name": "repo", "description": "Repository to explain", "required": true}
                    ]
                },
                {
                    "name": "find_implementation",
                    "description": "Find where a specific feature or algorithm is implemented",
                    "arguments": [
                        {"name": "repo", "description": "Repository to search", "required": true},
                        {"name": "feature", "description": "Feature or algorithm to find", "required": true}
                    ]
                }
            ]
        }),
    )
}

fn handle_prompts_get(id: Option<Value>, params: Value) -> JsonRpcResponse {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(json!({}));

    match name {
        "explain_codebase" => {
            let repo = arguments
                .get("repo")
                .and_then(|v| v.as_str())
                .unwrap_or("<repository>");
            jsonrpc_success(
                id,
                json!({
                    "description": "Get an overview of a codebase's architecture and key components",
                    "messages": [{
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": format!("Please explain the architecture and key components of the '{repo}' repository. Use get_project_structure, find_symbols, get_file, and search_code to gather information.")
                        }
                    }]
                }),
            )
        }
        "find_implementation" => {
            let repo = arguments
                .get("repo")
                .and_then(|v| v.as_str())
                .unwrap_or("<repository>");
            let feature = arguments
                .get("feature")
                .and_then(|v| v.as_str())
                .unwrap_or("<feature>");
            jsonrpc_success(
                id,
                json!({
                    "description": "Find where a specific feature or algorithm is implemented",
                    "messages": [{
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": format!("Find where the '{feature}' feature is implemented in the '{repo}' repository. Use search_code, find_symbols, and get_project_structure to locate the relevant code.")
                        }
                    }]
                }),
            )
        }
        _ => jsonrpc_error(id, -32602, &format!("Prompt not found: {name}")),
    }
}

// ── JSON-RPC Response helpers ────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcErrorValue>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcErrorValue {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

fn jsonrpc_success(id: Option<Value>, result: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: Some(result),
        error: None,
    }
}

fn jsonrpc_error(id: Option<Value>, code: i32, message: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(JsonRpcErrorValue {
            code,
            message: message.to_string(),
            data: None,
        }),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jsonrpc_success_response() {
        let resp = jsonrpc_success(Some(json!("test-id")), json!({"key": "value"}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"result\""));
        assert!(json.contains("\"key\":\"value\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn test_jsonrpc_error_response() {
        let resp = jsonrpc_error(Some(json!(1)), -32000, "something broke");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"error\""));
        assert!(json.contains("something broke"));
        assert!(!json.contains("\"result\""));
    }

    #[test]
    fn test_session_id_extraction() {
        let sessions: DashMap<String, SessionState> = DashMap::new();
        let mut headers = HeaderMap::new();
        headers.insert("x-session-id", "test-123".parse().unwrap());

        let sid = get_or_create_session_id(&headers, &sessions);
        assert_eq!(sid, "test-123");
        assert!(sessions.contains_key("test-123"));
    }

    #[test]
    fn test_session_id_generation() {
        let sessions: DashMap<String, SessionState> = DashMap::new();
        let headers = HeaderMap::new();

        let sid = get_or_create_session_id(&headers, &sessions);
        assert!(!sid.is_empty());
        // UUID v4 is 36 chars: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        assert_eq!(sid.len(), 36);
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn test_health_response_format() {
        let resp = json!(serde_json::from_str::<Value>(
            &serde_json::to_string(&json!({
                "status": "ok",
                "service": SERVER_NAME,
                "version": SERVER_VERSION,
                "protocol": MCP_VERSION,
            }))
            .unwrap()
        ));
        assert_eq!(resp["status"], "ok");
        assert_eq!(resp["service"], "narsil-mcp");
        assert_eq!(resp["protocol"], "2024-11-05");
    }
}
