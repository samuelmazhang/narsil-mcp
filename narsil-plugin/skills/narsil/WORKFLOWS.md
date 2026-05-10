# Narsil Workflows

Detailed workflow examples for common code intelligence tasks.

## Codebase Exploration

### First Contact with Unknown Codebase

Goal: Understand structure and main components.

```
1. list_repos
   → Get repository name(s)

2. get_project_structure(repo, max_depth=3)
   → See top-level directory structure

3. find_symbols(repo, symbol_type="class", file_pattern="src/**/*")
   → Find main data structures

4. find_symbols(repo, symbol_type="function", pattern="*main*")
   → Find entry points

5. get_import_graph(repo)
   → Understand module dependencies

6. find_circular_imports(repo)
   → Identify potential issues

7. get_ccg_manifest(repo)   # optional, requires --graph
   → Compact AI-context-friendly manifest with symbol counts and security posture
```

> Note: `explain_codebase` is registered as an MCP **prompt**, not a tool. It can't be called from a tool-calling workflow — surface it through the client's prompt UI (or via the `/narsil:explore` slash command, which captures the same intent through the steps above).

### Finding Where a Feature Lives

Goal: Locate implementation of a specific feature.

```
1. hybrid_search(query="feature description in natural language")
   → Semantic search for relevant code (BM25 + TF-IDF, Reciprocal Rank Fusion)

2. workspace_symbol_search(query="FeatureName")
   → Fuzzy search for related symbols

3. For each candidate:
   find_symbol_usages(repo, symbol)
   → Confirm it's widely used

4. get_symbol_definition(repo, symbol)
   → Read the implementation
```

> Note: `find_implementation` is registered as an MCP **prompt**, not a tool. The slash command `/narsil:find-feature` runs the equivalent tool sequence above.

### Understanding Module Dependencies

Goal: Map how modules connect.

```
1. get_dependencies(repo, path, direction="both")
   → See imports and importers for specific file

2. get_import_graph(repo)
   → Full dependency graph

3. find_circular_imports(repo)
   → Identify problematic cycles

4. get_export_map(repo, path)
   → See what a module exposes
```

## Security Workflows

### Full Security Audit

Goal: Comprehensive vulnerability assessment.

```
1. get_security_summary(repo)
   → Overview of security posture

2. scan_security(repo, severity_threshold="medium")
   → All medium+ findings

3. check_owasp_top10(repo)
   → Web application vulnerabilities

4. check_cwe_top25(repo)
   → Most dangerous software weaknesses

5. check_dependencies(repo)
   → Known CVEs in dependencies

6. check_licenses(repo, project_license="MIT")
   → License compatibility issues

7. For critical findings:
   explain_vulnerability(rule_id=...)
   → Understand the issue

8. For each finding:
   suggest_fix(repo, path, line)
   → Get remediation guidance
```

### Injection Vulnerability Deep Dive

Goal: Find and trace injection flaws.

```
1. find_injection_vulnerabilities(repo, vulnerability_types=["sql", "xss", "command"])
   → Find injection points

2. get_taint_sources(repo, source_types=["user_input", "network"])
   → Identify where tainted data enters

3. For each vulnerability:
   trace_taint(repo, path, line)
   → Follow tainted data flow

4. get_typed_taint_flow(repo, path, source_line)
   → Enhanced analysis with type info
```

### Dependency Risk Assessment

Goal: Assess supply chain security.

```
1. generate_sbom(repo, format="cyclonedx")
   → Complete software bill of materials

2. check_dependencies(repo, include_dev=true, severity_threshold="low")
   → All known vulnerabilities

3. find_upgrade_path(repo)
   → Safe upgrade paths for vulnerable deps

4. check_licenses(repo, fail_on_copyleft=true)
   → License compliance issues
```

## Call Graph Analysis

### Understanding Function Impact

Goal: Assess impact of changing a function.

```
1. get_callers(repo, function, transitive=true, max_depth=5)
   → All functions that depend on this one

2. get_callees(repo, function, transitive=true)
   → All functions this one depends on

3. get_complexity(repo, function)
   → Cyclomatic and cognitive complexity

4. get_function_hotspots(repo, min_connections=10)
   → Identify highly connected functions
```

### Tracing Execution Path

Goal: Understand how data flows from A to B.

```
1. find_call_path(repo, from="entry_function", to="target_function")
   → Path between two functions

2. For each function in path:
   get_control_flow(repo, path, function)
   → See branches and loops

3. get_data_flow(repo, path, function)
   → Track variable definitions and uses
```

### Finding Dead Code

Goal: Identify unused code.

```
1. get_function_hotspots(repo, min_connections=0)
   → Find functions with zero callers

2. find_dead_code(repo, path)
   → Unreachable code blocks

3. find_dead_stores(repo, path)
   → Assignments never read
```

### Finding Code Clones (Refactoring Targets)

Goal: Detect duplicate or similar code patterns.

```
1. find_semantic_clones(repo, path, function)
   → Find Type-3/4 code clones (similar logic, different syntax)

2. find_similar_to_symbol(repo, symbol)
   → Find code patterns similar to a specific function

3. find_similar_code(query="<paste code snippet>")
   → Find code similar to a given snippet

4. For each clone found:
   get_symbol_definition(repo, symbol)
   → Compare the implementations
```

### Symbol Reference Tracking

Goal: Understand how a symbol is used across the codebase.

```
1. find_references(repo, symbol)
   → All references to the symbol

2. find_symbol_usages(repo, symbol, include_imports=true)
   → Cross-file usages including imports

3. get_export_map(repo, path)
   → See what the module exports

4. get_dependencies(repo, path, direction="imported_by")
   → Find files that depend on this module
```

## Static Analysis Workflows

### Type Analysis (Python/JS/TS)

Goal: Understand types without running type checker.

```
1. infer_types(repo, path, function)
   → Inferred types for variables

2. check_type_errors(repo, path)
   → Potential type mismatches

3. find_uninitialized(repo, path)
   → Variables used before assignment
```

### Control Flow Analysis

Goal: Understand function logic flow.

```
1. get_control_flow(repo, path, function)
   → Basic blocks, branches, loops

2. find_dead_code(repo, path, function)
   → Unreachable code in function

3. get_reaching_definitions(repo, path, function)
   → Which assignments reach each point
```

## Git History Analysis

Requires `--git` flag.

### Understanding Code Evolution

Goal: Track how code changed over time.

```
1. get_file_history(repo, path, max_commits=20)
   → Recent changes to file

2. get_symbol_history(repo, path, symbol, max_commits=10)
   → Commits that touched specific function

3. get_blame(repo, path, start_line=X, end_line=Y)
   → Who wrote each line

4. get_commit_diff(repo, commit)
   → See exact changes in a commit
```

### Finding Code Hotspots

Goal: Identify high-churn areas needing attention.

```
1. get_hotspots(repo, days=30, min_complexity=10)
   → Files with high churn + complexity

2. get_contributors(repo, path)
   → Who knows this code best

3. get_recent_changes(repo, days=7)
   → Recent activity in repo
```

### Pre-Commit Analysis

Goal: Check changes before committing.

```
1. get_modified_files(repo)
   → See uncommitted changes

2. get_branch_info(repo)
   → Current branch and status

3. For each modified file:
   scan_security(repo, path=modified_file)
   → Security check on changes
```

## Knowledge Graph (SPARQL / CCG)

Requires `--graph` flag at startup.

### Quick SPARQL Exploration

Goal: Run analytical queries against the indexed RDF graph.

```
1. list_sparql_templates()
   → See built-in templates (e.g., most-called functions, dependency cycles)

2. run_sparql_template(template="<name>", params={...})
   → Execute a parameterised template

3. sparql_query(query="SELECT ?fn ?file WHERE { ... }")
   → Custom SPARQL for ad-hoc analysis
```

### Exporting a Code Context Graph (CCG) for handoff

Goal: Produce a portable, layered description of a repo for AI agents or external indexers.

```
1. get_ccg_manifest(repo)
   → Layer 0: tiny JSON-LD manifest (identity, languages, symbol counts, security posture)

2. export_ccg_architecture(repo, output_path="ccg-arch.jsonld")
   → Layer 1: ~10-50KB module/architecture overview

3. export_ccg_index(repo, output_path="ccg-index.nq.gz")
   → Layer 2: gzipped N-Quads symbol index

4. export_ccg_full(repo, output_path="ccg-full.nq.gz")
   → Layer 3: full detail (largest, slowest)

5. get_ccg_acl(repo)
   → Generate WebACL for hosted/shared CCG

# Or do everything at once:
6. export_ccg(repo, output_dir="./ccg-bundle")
   → Bundle of all layers
```

### Importing & Querying a Remote CCG

Goal: Pull in a published CCG for cross-repo analysis.

```
1. import_ccg_from_registry(repo_url="https://github.com/owner/repo")
   → Pull from codecontextgraph.com registry

   # or:
   import_ccg(source="https://example.com/ccg.nq.gz")

2. query_ccg(repo, query="SELECT ... WHERE { ... }")
   → SPARQL against the imported CCG
```

## Remote Repositories (GitHub)

Requires `--remote` flag and `GITHUB_TOKEN` env var.

### Cross-repo investigation without local clone

```
1. add_remote_repo(url="https://github.com/owner/repo")
   → Clone + index a remote repo

2. list_remote_files(url="https://github.com/owner/repo", path="src/")
   → Browse without cloning (uses GitHub API)

3. get_remote_file(url="https://github.com/owner/repo", path="src/main.rs")
   → Fetch a single file via API
```

## Search Strategy

### When to Use Each Search Tool

| Scenario | Tool | Why |
|----------|------|-----|
| Know exact function name | `find_symbols` | Direct lookup |
| Know partial name | `workspace_symbol_search` | Fuzzy matching |
| Searching for concept | `hybrid_search` | Semantic understanding |
| Have code to match | `find_similar_code` | Pattern similarity |
| Looking for text | `search_code` | Keyword search |
| Need chunks | `search_chunks` | AST-aware results |

### Narrowing Large Result Sets

```
1. Start broad:
   search_code(query="authentication", max_results=50)

2. Filter by file type:
   search_code(query="authentication", file_pattern="*.py")

3. Focus on specific directory:
   search_code(query="authentication", repo="myrepo", file_pattern="src/auth/**/*")

4. Search within chunks:
   search_chunks(query="authentication", chunk_type="function")
```

## Performance Tips

1. **Use `file_pattern`** - Always filter when you know the file types
2. **Use `max_results`** - Don't fetch more than you need
3. **Batch related queries** - Call multiple tools in parallel when independent
4. **Check feature status first** - Use `get_index_status` to avoid wasted calls
5. **Use excerpts over full files** - `get_excerpt` is faster than `get_file` for specific lines
