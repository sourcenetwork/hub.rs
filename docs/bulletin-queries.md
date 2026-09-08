# Bulletin collection queries

Collection queries return complete results only within their work budget:

- At most 128 inspected records.
- At most 1 MiB of inspected storage keys and encoded record values.
- A selection prefix no longer than 64 KiB.
- For glob queries, a pattern no longer than 4 KiB.

The same collector serves namespace lists, namespace collaborators, namespace
posts, all posts and glob-selected posts. Nonmatching glob records count against
the inspection budget. Oversized queries return an explicit error; partial
results are never returned as complete. Malformed records and record/key
mismatches also return errors instead of being skipped.

For larger collections, use `HubClient::list_bulletin_namespaces`,
`list_bulletin_posts` or `list_bulletin_collaborators`. These existing native APIs
verify certified prefix pages and return continuation cursors. Apply any glob
filter to each verified post page locally. Each page has its own selected
revision; pagination does not pin a historical snapshot.

Globs retain literal matching with `*` spanning any sequence, including `/`.
Matching uses anchored prefix/suffix checks and forward searches for literal
segments, with no recursive backtracking. No other wildcard syntax is interpreted.

These read limits do not cap stored history or establish a measured execution
throughput target. Transport response limits apply separately from stored-byte
inspection limits.
