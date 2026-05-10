/// Tool filtering based on configuration and feature flags
///
/// Converts EngineOptions and ToolConfig into a filtered list of enabled tools.
/// Must complete in <1ms for responsive tool list queries.
use crate::config::editor::get_editor_preset_or_full;
use crate::config::preset::Preset;
use crate::config::schema::ToolConfig;
use crate::index::EngineOptions;
use crate::tool_metadata::{FeatureFlag, PerformanceImpact, ToolMetadata, TOOL_METADATA};
use std::collections::HashSet;

/// Client information from MCP initialize
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub name: String,
    pub version: Option<String>,
}

/// Tool filter that applies configuration to determine enabled tools
pub struct ToolFilter {
    config: ToolConfig,
    enabled_flags: HashSet<FeatureFlag>,
    preset: Preset,
}

impl ToolFilter {
    /// Create a new tool filter
    pub fn new(
        config: ToolConfig,
        engine_options: &EngineOptions,
        client_info: Option<ClientInfo>,
    ) -> Self {
        let enabled_flags = Self::convert_engine_options(engine_options);

        // Determine preset with priority: config.preset > client_info > Full
        let preset = if let Some(ref preset_str) = config.preset {
            // Config preset has highest priority
            Preset::parse(preset_str).unwrap_or(Preset::Full)
        } else if let Some(ref client) = client_info {
            // Fall back to client-based preset
            get_editor_preset_or_full(&client.name)
        } else {
            // Default to full preset
            Preset::Full
        };

        Self {
            config,
            enabled_flags,
            preset,
        }
    }

    /// Convert EngineOptions to a set of FeatureFlags
    pub fn convert_engine_options(options: &EngineOptions) -> HashSet<FeatureFlag> {
        let mut flags = HashSet::new();

        if options.git_enabled {
            flags.insert(FeatureFlag::Git);
        }
        if options.call_graph_enabled {
            flags.insert(FeatureFlag::CallGraph);
        }
        if options.persist_enabled {
            flags.insert(FeatureFlag::Persist);
        }
        if options.watch_enabled {
            flags.insert(FeatureFlag::Watch);
        }
        if options.lsp_config.enabled {
            flags.insert(FeatureFlag::Lsp);
        }
        if options.neural_config.enabled {
            flags.insert(FeatureFlag::Neural);
        }
        if options.remote_enabled {
            flags.insert(FeatureFlag::Remote);
        }
        #[cfg(feature = "graph")]
        if options.graph_enabled {
            flags.insert(FeatureFlag::Graph);
        }

        flags
    }

    /// Get the list of enabled tools based on configuration and flags.
    ///
    /// The `Full` preset is treated as an explicit "expose everything"
    /// directive: it bypasses the `max_tool_count` cap entirely so the user
    /// gets the full registry (subject to the per-tool feature-flag check).
    /// Other presets (Minimal, Balanced, SecurityFocused) honour the cap so
    /// editor token-budgets stay predictable.
    pub fn get_enabled_tools(&self) -> Vec<&'static str> {
        let mut enabled_tools = Vec::new();

        // Iterate through all tools in the metadata registry
        for (tool_name, metadata) in TOOL_METADATA.iter() {
            if self.is_tool_enabled(tool_name, metadata) {
                enabled_tools.push(*tool_name);
            }
        }

        if matches!(self.preset, Preset::Full) {
            return enabled_tools;
        }

        // Apply performance budget for non-Full presets.
        self.apply_performance_budget(enabled_tools)
    }

    /// Check if a specific tool should be enabled
    fn is_tool_enabled(&self, tool_name: &str, metadata: &ToolMetadata) -> bool {
        // 1. Check tool-level override first (highest priority)
        if let Some(override_config) = self.config.tools.overrides.get(tool_name) {
            if !override_config.enabled {
                return false; // Explicitly disabled
            }
            // If explicitly enabled via override, still need to check required flags
        }

        // 2. Check if preset explicitly disables this tool
        let disabled_by_preset = self.preset.get_disabled_tools();
        if disabled_by_preset.contains(tool_name) {
            return false; // Disabled by preset
        }

        // 3. Check if preset has an enabled whitelist
        let enabled_by_preset = self.preset.get_enabled_tools();
        if !enabled_by_preset.is_empty() {
            // Preset has a whitelist (not Full preset)
            if !enabled_by_preset.contains(tool_name) {
                return false; // Not in whitelist
            }
        }
        // If preset is Full (empty whitelist), all tools are allowed

        // 4. Check if tool's category is enabled.
        // Use Display, not Debug — Debug emits the raw variant identifier
        // (`Lsp`) while the YAML/config key is the canonical name (`LSP`),
        // so Debug silently misses LSP-category overrides. See issue #23.
        let category_name = metadata.category.to_string();
        if let Some(category_config) = self.config.tools.categories.get(&category_name) {
            if !category_config.enabled {
                return false; // Category disabled
            }
        }

        // 5. Check required feature flags
        if !metadata.required_flags.is_empty() {
            // Tool requires specific flags - must have ALL of them
            for required_flag in &metadata.required_flags {
                if !self.enabled_flags.contains(required_flag) {
                    return false; // Missing required flag
                }
            }
        }

        // 6. All checks passed
        true
    }

    /// Apply performance budget (max_tool_count)
    fn apply_performance_budget(&self, mut tools: Vec<&'static str>) -> Vec<&'static str> {
        let max_count = self.config.performance.max_tool_count;

        if tools.len() <= max_count {
            return tools; // Under budget, no trimming needed
        }

        // Prioritize tools by performance impact (Low > Medium > High)
        // Use tool name as secondary key for deterministic ordering
        // (DashMap iteration order is non-deterministic)
        tools.sort_by_key(|tool_name| {
            TOOL_METADATA
                .get(tool_name)
                .map(|meta| {
                    (
                        match meta.performance {
                            PerformanceImpact::Low => 0,
                            PerformanceImpact::Medium => 1,
                            PerformanceImpact::High => 2,
                        },
                        *tool_name, // Secondary sort by name for determinism
                    )
                })
                .unwrap_or((999, *tool_name)) // Unknown tools go last
        });

        // Take top N tools
        tools.truncate(max_count);
        tools
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{CategoryConfig, ToolOverride};
    use std::collections::HashMap;

    #[test]
    fn test_convert_engine_options_all_enabled() {
        let options = EngineOptions {
            git_enabled: true,
            call_graph_enabled: true,
            persist_enabled: true,
            watch_enabled: true,
            remote_enabled: true,
            lsp_config: crate::lsp::LspConfig {
                enabled: true,
                ..Default::default()
            },
            neural_config: crate::neural::NeuralConfig {
                enabled: true,
                ..Default::default()
            },
            #[cfg(feature = "graph")]
            graph_enabled: true,
            ..Default::default()
        };

        let flags = ToolFilter::convert_engine_options(&options);

        // 7 baseline flags + Graph when the graph feature is compiled in.
        let expected_count = if cfg!(feature = "graph") { 8 } else { 7 };
        assert_eq!(flags.len(), expected_count);
        assert!(flags.contains(&FeatureFlag::Git));
        assert!(flags.contains(&FeatureFlag::CallGraph));
        assert!(flags.contains(&FeatureFlag::Persist));
        assert!(flags.contains(&FeatureFlag::Watch));
        assert!(flags.contains(&FeatureFlag::Lsp));
        assert!(flags.contains(&FeatureFlag::Neural));
        assert!(flags.contains(&FeatureFlag::Remote));
        #[cfg(feature = "graph")]
        assert!(flags.contains(&FeatureFlag::Graph));
    }

    #[test]
    fn test_convert_engine_options_none_enabled() {
        let options = EngineOptions::default();
        let flags = ToolFilter::convert_engine_options(&options);
        assert_eq!(flags.len(), 0);
    }

    #[test]
    fn test_is_tool_enabled_basic() {
        let config = ToolConfig::default();
        let options = EngineOptions::default();
        let filter = ToolFilter::new(config, &options, None);

        // list_repos requires no flags, should be enabled
        let meta = TOOL_METADATA.get("list_repos").unwrap();
        assert!(filter.is_tool_enabled("list_repos", meta));
    }

    #[test]
    fn test_is_tool_enabled_with_flag() {
        let config = ToolConfig::default();
        let options = EngineOptions {
            git_enabled: true,
            ..Default::default()
        };

        let filter = ToolFilter::new(config, &options, None);

        // get_blame requires Git flag
        let meta = TOOL_METADATA.get("get_blame").unwrap();
        assert!(filter.is_tool_enabled("get_blame", meta));
    }

    #[test]
    fn test_is_tool_enabled_without_required_flag() {
        let config = ToolConfig::default();
        let options = EngineOptions::default(); // git_enabled = false

        let filter = ToolFilter::new(config, &options, None);

        // get_blame requires Git flag
        let meta = TOOL_METADATA.get("get_blame").unwrap();
        assert!(!filter.is_tool_enabled("get_blame", meta));
    }

    #[test]
    fn test_is_tool_enabled_category_disabled() {
        let mut config = ToolConfig::default();
        config.tools.categories.insert(
            "Git".to_string(),
            CategoryConfig {
                enabled: false,
                description: None,
                required_flags: vec![],
                config: HashMap::new(),
            },
        );

        let options = EngineOptions {
            git_enabled: true, // Flag enabled, but category disabled
            ..Default::default()
        };

        let filter = ToolFilter::new(config, &options, None);

        let meta = TOOL_METADATA.get("get_blame").unwrap();
        assert!(!filter.is_tool_enabled("get_blame", meta));
    }

    #[test]
    fn test_is_tool_enabled_override_disabled() {
        let mut config = ToolConfig::default();
        config.tools.overrides.insert(
            "list_repos".to_string(),
            ToolOverride {
                enabled: false,
                reason: Some("Test".to_string()),
                required_flags: vec![],
                config: HashMap::new(),
                performance_impact: None,
                requires_api_key: false,
            },
        );

        let options = EngineOptions::default();
        let filter = ToolFilter::new(config, &options, None);

        let meta = TOOL_METADATA.get("list_repos").unwrap();
        assert!(!filter.is_tool_enabled("list_repos", meta));
    }

    #[test]
    fn test_apply_performance_budget() {
        let mut config = ToolConfig::default();
        config.performance.max_tool_count = 5;

        let options = EngineOptions::default();
        let filter = ToolFilter::new(config, &options, None);

        let tools = vec![
            "list_repos",
            "find_symbols",
            "search_code",
            "get_file",
            "get_project_structure",
            "find_references",
            "get_dependencies",
        ];

        let filtered = filter.apply_performance_budget(tools);
        assert_eq!(filtered.len(), 5);
    }

    #[test]
    fn test_performance_budget_prioritizes_low_impact() {
        let mut config = ToolConfig::default();
        config.performance.max_tool_count = 10;
        // Use a non-Full preset so the budget is actually applied —
        // Full preset bypasses the cap by design.
        config.preset = Some("balanced".to_string());

        let options = EngineOptions {
            git_enabled: true,
            call_graph_enabled: true,
            neural_config: crate::neural::NeuralConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let filter = ToolFilter::new(config, &options, None);
        let enabled = filter.get_enabled_tools();

        assert!(enabled.len() <= 10);

        // Check that low-impact tools are prioritized over high-impact ones
        let mut low_impact_count = 0;
        let mut high_impact_count = 0;

        for tool_name in &enabled {
            if let Some(meta) = TOOL_METADATA.get(tool_name) {
                match meta.performance {
                    PerformanceImpact::Low => low_impact_count += 1,
                    PerformanceImpact::High => high_impact_count += 1,
                    _ => {}
                }
            }
        }

        // Should have more low-impact tools than high-impact tools
        assert!(
            low_impact_count >= high_impact_count,
            "Should prioritize low-impact tools: low={}, high={}",
            low_impact_count,
            high_impact_count
        );
    }

    /// Issue #23: an LSP-category tool's category lookup must succeed via the
    /// canonical `Display` representation of `ToolCategory::Lsp` (which is
    /// `"LSP"`). Using `Debug` produces `"Lsp"`, silently misses the YAML key,
    /// and leaves Lsp tools unaffected by `enabled: false` overrides.
    #[test]
    fn test_lsp_category_lookup_uses_display() {
        let mut config = ToolConfig::default();
        config.tools.categories.insert(
            "LSP".to_string(),
            CategoryConfig {
                enabled: false,
                description: None,
                required_flags: vec![],
                config: HashMap::new(),
            },
        );
        // Need a non-Full preset so the LSP tool is filtered by category, not
        // by Full's "all-or-nothing" semantics.
        config.preset = Some("full".to_string());

        let options = EngineOptions {
            lsp_config: crate::lsp::LspConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let filter = ToolFilter::new(config, &options, None);

        // get_hover_info is in ToolCategory::Lsp.
        let meta = TOOL_METADATA
            .get("get_hover_info")
            .expect("get_hover_info metadata exists");
        assert!(
            !filter.is_tool_enabled("get_hover_info", meta),
            "LSP-category tool should be filtered out when LSP category is disabled"
        );
    }

    /// Issue #23: `convert_engine_options` must propagate `remote_enabled` to
    /// `FeatureFlag::Remote` so Remote-category tools can surface when
    /// `--remote` is passed.
    #[test]
    fn test_convert_engine_options_propagates_remote() {
        let options = EngineOptions {
            remote_enabled: true,
            ..Default::default()
        };
        let flags = ToolFilter::convert_engine_options(&options);
        assert!(
            flags.contains(&FeatureFlag::Remote),
            "FeatureFlag::Remote must be set when EngineOptions.remote_enabled is true"
        );
    }

    /// Issue #23: under `feature = "graph"`, `convert_engine_options` must
    /// propagate `graph_enabled` to `FeatureFlag::Graph` so SPARQL/CCG tools
    /// can surface when `--graph` is passed.
    #[cfg(feature = "graph")]
    #[test]
    fn test_convert_engine_options_propagates_graph() {
        let options = EngineOptions {
            graph_enabled: true,
            ..Default::default()
        };
        let flags = ToolFilter::convert_engine_options(&options);
        assert!(
            flags.contains(&FeatureFlag::Graph),
            "FeatureFlag::Graph must be set when EngineOptions.graph_enabled is true"
        );
    }

    /// Issue #23: the Full preset should expose every registered tool whose
    /// feature requirements are met, regardless of `max_tool_count`. Without
    /// this bypass, `max_tool_count: 76` silently truncated the 90-tool registry
    /// even when the user explicitly asked for the Full preset.
    #[test]
    fn test_full_preset_bypasses_performance_budget() {
        let mut config = ToolConfig::default();
        // Set a tiny budget that would otherwise truncate.
        config.performance.max_tool_count = 5;
        config.preset = Some("full".to_string());

        let options = EngineOptions::default();
        let filter = ToolFilter::new(config, &options, None);
        let enabled = filter.get_enabled_tools();

        // Full preset returns all tools whose required_flags are satisfied;
        // with no flags enabled, only flag-less tools surface — but that count
        // is far larger than the tiny `max_tool_count` budget would allow.
        assert!(
            enabled.len() > 5,
            "Full preset must bypass max_tool_count cap; got {} tools",
            enabled.len()
        );
    }

    /// Issue #23: with `--remote` enabled, the `add_remote_repo` tool should
    /// actually surface in `get_enabled_tools`. Without `FeatureFlag::Remote`
    /// being propagated from `EngineOptions.remote_enabled`, it never did.
    #[test]
    fn test_remote_tool_surfaces_with_remote_flag() {
        let config = ToolConfig::default();
        let options = EngineOptions {
            remote_enabled: true,
            ..Default::default()
        };
        let filter = ToolFilter::new(config, &options, None);
        let enabled = filter.get_enabled_tools();
        assert!(
            enabled.contains(&"add_remote_repo"),
            "add_remote_repo should surface when --remote is enabled; got {} tools",
            enabled.len()
        );
    }
}
