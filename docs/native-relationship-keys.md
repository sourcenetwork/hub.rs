# Native relationship keys

Native relationships use `relationship/{policy_id}/v2/{resource_hex}/{object_hex}/{relation_hex}/{subject_digest}`. Field encodings are lowercase hexadecimal UTF-8 bytes. Separators cannot occur inside an encoded field, so object and relation prefixes are exact even for path-like identifiers. Policy IDs are the canonical generated policy IDs.

The subject digest is lowercase hexadecimal SHA-256 over `vera/acp-subject/v1` followed by one zero byte and the compact JSON encoding of the typed subject. The encoding uses the externally tagged variants `Entity`, `Wildcard`, `TypedWildcard`, and `EntitySet`. Entity-set fields are ordered `resource`, `object_id`, `relation`; typed wildcards carry `resource`. The digest replaces the shared engine's 64-bit storage hash. Changes to this canonical representation require a coordinated format upgrade.

The builders live in `hub_modules::acp::keys`; native permission, owner and relationship proof readers use those builders. The shared Zanzibar engine and Defra's own persisted storage format are unchanged. Callers must not construct native keys with `Relationship::storage_key()`.

Native genesis fingerprints bind `vera/native-genesis/v2` followed by one zero byte and the serialized genesis configuration. Existing native genesis records and initialization intents from the previous format cannot be reopened by this version. Retained relationships are also checked against their canonical keys before publishing recovered state. Startup does not rewrite keys or authenticated history: existing deployments require an explicit migration and coordinated consumer upgrade. Fresh deployments use the new format throughout.
