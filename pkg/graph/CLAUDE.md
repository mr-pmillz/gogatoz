# pkg/graph

Directed acyclic graph (DAG) implementation for modeling GitLab CI/CD job execution dependencies. Converts parsed `.gitlab-ci.yml` documents into a graph where nodes represent CI jobs and edges represent dependencies (explicit `needs:` or implicit stage-based ordering). Validated for cycles at construction time via Kahn's algorithm.

## Files

| File | Purpose |
|------|---------|
| `graph.go` | Core graph structure, node types (JobNode, WorkflowNode, RepoNode), adjacency lists, tag indexing, topological sort |
| `builder.go` | `Build()` constructs graph from parsed pipeline Document; stage-based fallback edge logic |

## Exported API

**Types:**
- `NodeType` (string) -- constants: `NodeJob`, `NodeWorkflow`, `NodeRepo`
- `Node` interface -- `ID() string`, `Type() NodeType`, `Tags() []string`
- `JobNode` -- Name, Stage, Needs, TagList
- `WorkflowNode` -- Name (reserved, unused currently)
- `RepoNode` -- Path (reserved for future multi-repo graphs)
- `Graph` -- Nodes (map), Succ/Pred (adjacency lists), TagIndex (tag->nodeIDs)

**Functions:**
- `New() *Graph` -- create empty graph
- `Graph.AddNode(n Node)` -- register node, index tags
- `Graph.AddEdge(fromID, toID)` -- add directed edge
- `Graph.Successors/Predecessors(id) []string` -- sorted copies of connected nodes
- `Graph.NodesWithTag(tag) []string` -- nodes carrying a tag
- `Graph.TopoSort() ([]string, error)` -- Kahn's algorithm; error on cycle
- `Build(doc *pipeline.Document) (*Graph, error)` -- construct from CI doc
- `Graph.SortedJobIDs() []string` -- stable-sorted job node IDs

## Internal Patterns

- **Adjacency list** with dual Succ/Pred maps for O(1) bidirectional lookup
- **Tag indexing** maps runner tags to job IDs for O(1) lookup
- **Dependency resolution**: explicit `needs:` override stage-based fallback; if no needs, edges added from all jobs in immediately previous stage
- **Duplicate avoidance**: AddNode/AddEdge check for existing entries
- **Deterministic topo sort**: `sort.Strings()` on queue ensures reproducible order

## Testing

- `graph_test.go` -- node/edge addition, tag indexing, cycle detection
- `builder_test.go` -- stage-based edges, explicit needs, cycle detection
- Fixtures use embedded YAML passed to `pipeline.Parse()`; `mustParse()` helper

## Dependencies

**Imports:**
- `pkg/pipeline` -- `Document`, `Job` types for `Build()`

**Depended on by:** None currently (future: analyze, attack for path analysis)

## Gotchas

1. **Dangling needs silently ignored** -- `needs: [non_existent_job]` skips the edge (no error)
2. **Stage-based fallback only if doc.Stages non-empty** -- no implicit edges without top-level `stages:` declaration
3. **Unknown stages auto-appended** -- jobs referencing undefined stages get them appended to stage order
4. **Tags are copied, not referenced** -- modifying node tags after AddNode doesn't affect graph
5. **Successors/Predecessors allocate new sorted slices** per call (not cached)
6. **No RemoveNode** -- graph is append-only
7. **Not thread-safe** -- caller must synchronize if shared across goroutines
