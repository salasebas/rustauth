# Mongo Adapter Upstream Checklist Implementation Plan

> **Guide note:** This document is a reusable implementation guide and tracking checklist, not a requirement to copy Better Auth line by line. If OpenAuth implements behavior differently but covers the same server-side capability more correctly, securely, or idiomatically, mark the matching checklist item as completed and document the intentional improvement.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the server-side behavior of Better Auth's `@better-auth/mongo-adapter` into an idiomatic Rust MongoDB adapter checklist that can be reused to track implementation progress.

**Architecture:** Treat the upstream package as a behavioral contract, not as code structure to copy. Implement a Rust adapter behind OpenAuth-owned storage traits, with explicit typed errors, typed ID conversion, MongoDB filter/pipeline builders, and optional transaction support.

**Tech Stack:** Rust, OpenAuth storage contracts, MongoDB Rust driver, BSON `ObjectId`/UUID support, async tests with MongoDB fakes or integration containers.

---

## Upstream Scope

Source package analyzed only from upstream:

- `upstream/better-auth/1.6.9/repository/packages/mongo-adapter/src/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/mongo-adapter/src/mongodb-adapter.ts`
- `upstream/better-auth/1.6.9/repository/packages/mongo-adapter/src/query-builders.ts`
- `upstream/better-auth/1.6.9/repository/packages/mongo-adapter/src/mongodb-adapter.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/mongo-adapter/README.md`
- `upstream/better-auth/1.6.9/repository/packages/mongo-adapter/package.json`
- `upstream/better-auth/1.6.9/repository/packages/mongo-adapter/vitest.config.ts`
- `upstream/better-auth/1.6.9/repository/packages/mongo-adapter/tsdown.config.ts`
- `upstream/better-auth/1.6.9/repository/packages/mongo-adapter/tsconfig.json`
- `upstream/better-auth/1.6.9/repository/packages/mongo-adapter/CHANGELOG.md`

Functional upstream dependencies reviewed because `mongo-adapter` delegates behavior to them:

- `upstream/better-auth/1.6.9/repository/packages/core/src/db/adapter/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/adapter/factory.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/adapter/get-model-name.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/adapter/get-default-model-name.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/adapter/get-field-name.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/adapter/get-default-field-name.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/adapter/get-field-attributes.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/adapter/get-id-field.ts`
- `upstream/better-auth/1.6.9/repository/packages/test-utils/src/adapter/suites/basic.ts`
- `upstream/better-auth/1.6.9/repository/packages/test-utils/src/adapter/suites/case-insensitive.ts`
- `upstream/better-auth/1.6.9/repository/packages/test-utils/src/adapter/suites/joins.ts`
- `upstream/better-auth/1.6.9/repository/packages/test-utils/src/adapter/suites/transactions.ts`
- `upstream/better-auth/1.6.9/repository/packages/test-utils/src/adapter/suites/uuid.ts`
- `upstream/better-auth/1.6.9/repository/packages/test-utils/src/adapter/suites/number-id.ts`

Excluded from the Rust server checklist:

- [ ] Do not port npm package metadata, `tsdown`, `vitest`, ESM export shape, or TypeScript-only packaging behavior.
- [ ] Do not add browser/client behavior; this upstream package is server adapter code only.
- [ ] Do not add endpoints, routes, `createAuthEndpoint`, or OpenAPI metadata for this adapter package; the upstream Mongo adapter exposes storage behavior only.
- [ ] Do not copy TypeScript factory structure mechanically; preserve behavior through Rust storage traits and explicit types.

## Proposed Rust File Map

These paths are proposed for implementation planning. Adjust names if the repository already has a stronger adapter layout when execution starts.

- [ ] Create or modify `crates/openauth-adapter-mongodb/Cargo.toml` for a MongoDB adapter crate gated behind explicit dependencies.
- [ ] Create or modify `crates/openauth-adapter-mongodb/src/lib.rs` for public exports and adapter constructor.
- [ ] Create `crates/openauth-adapter-mongodb/src/config.rs` for adapter config and ID strategy.
- [ ] Create `crates/openauth-adapter-mongodb/src/error.rs` for typed Mongo adapter errors.
- [ ] Create `crates/openauth-adapter-mongodb/src/ids.rs` for `ObjectId`, BSON UUID, custom ID, FK, and output conversion.
- [ ] Create `crates/openauth-adapter-mongodb/src/filter.rs` for `Where` to MongoDB filter conversion.
- [ ] Create `crates/openauth-adapter-mongodb/src/regex.rs` for escaped regex and insensitive operators.
- [ ] Create `crates/openauth-adapter-mongodb/src/pipeline.rs` for aggregate pipeline, projection, sort, skip, limit, and join builders.
- [ ] Create `crates/openauth-adapter-mongodb/src/adapter.rs` for CRUD/count/delete behavior.
- [ ] Create `crates/openauth-adapter-mongodb/src/transaction.rs` for optional MongoDB transaction handling.
- [ ] Create `crates/openauth-adapter-mongodb/src/model.rs` for model/collection name resolution, custom model names, field names, and pluralization if this is not already owned by core storage code.
- [ ] Create `crates/openauth-adapter-mongodb/src/transform.rs` for adapter-local input/output transforms if this behavior is not already owned by core storage code.
- [ ] Create `crates/openauth-adapter-mongodb/src/telemetry.rs` only if OpenAuth adapter operations need Mongo-specific span metadata outside the core storage layer.
- [ ] Create `crates/openauth-adapter-mongodb/tests/ids.rs` for ID conversion behavior.
- [ ] Create `crates/openauth-adapter-mongodb/tests/filter.rs` for query builder behavior.
- [ ] Create `crates/openauth-adapter-mongodb/tests/adapter.rs` for CRUD/count/delete behavior.
- [ ] Create `crates/openauth-adapter-mongodb/tests/join.rs` for join pipeline behavior.
- [ ] Create `crates/openauth-adapter-mongodb/tests/transaction.rs` for transaction behavior.
- [ ] Create `crates/openauth-adapter-mongodb/tests/model_mapping.rs` for custom model names, custom field names, and pluralization behavior.
- [ ] Create `crates/openauth-adapter-mongodb/tests/transforms.rs` for default values, `force_allow_id`, JSON/string transforms, dates, booleans, arrays, and custom field transforms if core does not already test them.

## Checklist

### Task 1: Public Adapter Surface

**Upstream reference:** `src/index.ts`, `src/mongodb-adapter.ts`

- [ ] Implement a public MongoDB adapter constructor equivalent to `mongodbAdapter(db, config)`.
- [ ] Accept a MongoDB database handle as the required server-side dependency.
- [ ] Accept optional adapter config without forcing transactions.
- [ ] Export the adapter constructor from the crate root.
- [ ] Keep the public API Rust-native: typed config struct, explicit `Result`, and no TypeScript-shaped dynamic options.
- [ ] Test that constructing the adapter with a database handle and default config succeeds.

### Task 2: Adapter Configuration

**Upstream reference:** `MongoDBAdapterConfig`

- [ ] Add optional MongoDB client/session source for transaction support.
- [ ] Add `debug_logs` behavior compatible with the core adapter logging contract.
- [ ] Add `use_plural` behavior for collection/table naming.
- [ ] Add `transaction` flag where default is enabled only when a MongoDB client is provided.
- [ ] Preserve the upstream warning behavior in docs/tests: standalone MongoDB deployments may require `transaction = false`.
- [ ] Test default config with no client disables transactions.
- [ ] Test config with a client enables transactions by default.
- [ ] Test config with a client and `transaction = false` disables transactions.
- [ ] Test `use_plural` is passed into collection/model naming.

### Task 3: Adapter Metadata and Storage Capabilities

**Upstream reference:** adapter factory config in `mongodb-adapter.ts`

- [ ] Set adapter ID equivalent to `mongodb-adapter`.
- [ ] Set adapter display name equivalent to `MongoDB Adapter`.
- [ ] Support input key mapping `id -> _id`.
- [ ] Support output key mapping `_id -> id`.
- [ ] Mark array fields as supported.
- [ ] Mark numeric IDs as unsupported.
- [ ] Add tests that input model IDs target MongoDB `_id`.
- [ ] Add tests that output MongoDB `_id` is returned as public `id`.
- [ ] Add tests that numeric ID strategies are rejected or unavailable.
- [ ] Preserve default capability values inherited from the upstream adapter factory: booleans supported, dates supported, JSON not marked as supported unless OpenAuth intentionally improves this, UUIDs not marked as natively generated by the DB adapter, arrays supported.
- [ ] Test JSON behavior explicitly: either match upstream stringified JSON behavior or document and test an intentional improvement to native BSON document storage.

### Task 4: Typed Errors

**Upstream reference:** `MongoAdapterError`

- [ ] Add typed error variant `InvalidId`.
- [ ] Add typed error variant `UnsupportedOperator`.
- [ ] Include the unsupported operator value in the error message or error data.
- [ ] Ensure invalid ID errors are returned as `Result::Err`, not panics.
- [ ] Ensure unsupported operator errors are returned as `Result::Err`, not panics.
- [ ] Test invalid non-string/non-BSON ID input for direct IDs.
- [ ] Test invalid non-string/non-BSON ID input inside ID arrays.
- [ ] Test unsupported `Where` operator returns `UnsupportedOperator`.

### Task 5: ID Strategy and Custom ID Generation

**Upstream reference:** `getCustomIdGenerator`, `coerceToIdType`, `isIdInstance`, `serializeID`, `customTransformInput`, `customTransformOutput`, `customIdGenerator`

- [ ] Support default ObjectId strategy.
- [ ] Support BSON UUID strategy equivalent to upstream `advanced.database.generateId = "uuid"`.
- [ ] Support custom string ID generation where MongoDB does not coerce IDs into ObjectId/UUID.
- [ ] Generate a new ObjectId string by default when the core contract requests an ID string.
- [ ] Respect `generate_id = false` or equivalent no-generation mode if OpenAuth exposes it.
- [ ] Respect `force_allow_id` or equivalent explicit caller override for create operations with supplied IDs.
- [ ] Ignore or reject caller-supplied create IDs when `force_allow_id` is false, matching the core contract chosen for OpenAuth.
- [ ] Coerce public `id` and internal `_id` string values to ObjectId under the default strategy.
- [ ] Coerce public `id` and internal `_id` string values to BSON UUID under the UUID strategy.
- [ ] Leave invalid ID strings as strings when upstream behavior catches parse failures and preserves the value.
- [ ] Reject non-string, non-ID, non-null scalar ID values where upstream throws `INVALID_ID`.
- [ ] Preserve `null` and missing ID/reference values where upstream preserves them.
- [ ] Convert arrays of ID values item-by-item.
- [ ] Preserve already-typed ObjectId values under the ObjectId strategy.
- [ ] Preserve already-typed BSON UUID values under the UUID strategy.
- [ ] Convert referenced foreign-key fields whose schema reference points to `id`.
- [ ] On create, generate an `_id` when the model data does not provide one and no custom ID generator is configured.
- [ ] On update, do not generate a new ID for missing ID/reference fields.
- [ ] On optional foreign-key update/create, allow `null` when the schema field is not required.
- [ ] Convert ObjectId output values to hex strings.
- [ ] Convert BSON UUID output values to UUID strings.
- [ ] Convert arrays of ObjectId/BSON UUID output values item-by-item.
- [ ] Test create stores `_id` as ObjectId when no ID strategy is configured.
- [ ] Test create stores `_id` as BSON UUID when UUID strategy is configured.
- [ ] Test create stores referenced `userId` or equivalent FK as BSON UUID when UUID strategy is configured.
- [ ] Test custom ID generator bypasses ObjectId/UUID coercion.
- [ ] Test supplied create ID with `force_allow_id = true`.
- [ ] Test supplied create ID without `force_allow_id`.
- [ ] Test no-generation mode if OpenAuth exposes it.
- [ ] Test ObjectId output converts to public string `id`.
- [ ] Test BSON UUID output converts to public string `id`.
- [ ] Test referenced FK output converts to public string values.
- [ ] Test array ID input/output conversion.

### Task 6: Regex Query Helpers

**Upstream reference:** `src/query-builders.ts`

- [ ] Implement `escape_for_mongo_regex(input, max_length = 256)`.
- [ ] Escape regex metacharacters: `. * + ? ^ $ { } ( ) | [ ] \`.
- [ ] Truncate escaped input source to 256 characters by default before building regex.
- [ ] Return an empty escaped value for non-string inputs only if the Rust API exposes a dynamic boundary; otherwise make non-string values unrepresentable.
- [ ] Implement case-insensitive equality as anchored regex with `i` option.
- [ ] Implement case-insensitive `IN` as `$or` of anchored regex filters.
- [ ] Implement case-insensitive empty `IN` as an always-false expression.
- [ ] Implement case-insensitive `NOT IN` as `$nor` of anchored regex filters.
- [ ] Implement case-insensitive empty `NOT IN` as an empty filter.
- [ ] Implement case-insensitive inequality as `$not` anchored regex with `i` option.
- [ ] Implement case-insensitive contains as `.*value.*` with escaped value and `i` option.
- [ ] Implement case-insensitive starts-with as `^value` with escaped value and `i` option.
- [ ] Implement case-insensitive ends-with as `value$` with escaped value and `i` option.
- [ ] Test regex metacharacter escaping.
- [ ] Test 256-character truncation.
- [ ] Test insensitive equality.
- [ ] Test insensitive `IN` with values.
- [ ] Test insensitive empty `IN`.
- [ ] Test insensitive `NOT IN` with values.
- [ ] Test insensitive empty `NOT IN`.
- [ ] Test insensitive inequality.
- [ ] Test insensitive contains, starts-with, and ends-with.

### Task 7: Where Clause Conversion

**Upstream reference:** `convertWhereClause`

- [ ] Convert empty `where` lists to an empty MongoDB filter.
- [ ] Resolve public field names through the schema field-name mapper.
- [ ] Convert public `id` field to MongoDB `_id`.
- [ ] Detect ID/reference fields and apply ID serialization to them.
- [ ] Do not apply insensitive regex behavior to `_id` or fields referencing `id`.
- [ ] Support `eq`.
- [ ] Support `in`.
- [ ] Support `not_in`.
- [ ] Support `gt`.
- [ ] Support `gte`.
- [ ] Support `lt`.
- [ ] Support `lte`.
- [ ] Support `ne`.
- [ ] Support `contains`.
- [ ] Support `starts_with`.
- [ ] Support `ends_with`.
- [ ] Validate `in` receives an array before building a MongoDB `$in` query.
- [ ] Convert string booleans to booleans for boolean fields when filtering.
- [ ] Convert numeric strings and numeric string arrays to numbers for number fields when filtering.
- [ ] Preserve `null` comparisons for `eq` and `ne`.
- [ ] Preserve JSON object filtering behavior by stringifying only if OpenAuth matches upstream's `supportsJSON: false`; otherwise document the native BSON improvement.
- [ ] Support sensitive string contains with escaped MongoDB regex and no `i` option.
- [ ] Support sensitive starts-with with escaped MongoDB regex and no `i` option.
- [ ] Support sensitive ends-with with escaped MongoDB regex and no `i` option.
- [ ] Support insensitive `eq`, `in`, `not_in`, `ne`, `contains`, `starts_with`, and `ends_with` for string fields.
- [ ] Treat array values as insensitive only when every array item is a string.
- [ ] Combine multiple `AND` conditions under `$and`.
- [ ] Combine multiple `OR` conditions under `$or`.
- [ ] Return the single condition directly when only one condition is provided.
- [ ] Test every supported operator with a non-ID field.
- [ ] Test every supported operator with an ID field where applicable.
- [ ] Test field-name mapping.
- [ ] Test ID-to-`_id` mapping.
- [ ] Test AND-only conversion.
- [ ] Test OR-only conversion.
- [ ] Test mixed AND/OR conversion.
- [ ] Test `in` with non-array input is rejected.
- [ ] Test numeric string filter coercion.
- [ ] Test boolean string filter coercion.
- [ ] Test `eq` with `null`.
- [ ] Test `ne` with `null`.
- [ ] Test JSON filter behavior.
- [ ] Test unsupported operator error.

### Task 8: Create Operation

**Upstream reference:** `create({ model, data })`

- [ ] Insert the transformed document into the MongoDB collection named for the model.
- [ ] Pass the active session when inside a transaction.
- [ ] Return the inserted document with public `id` derived from MongoDB `inserted_id`.
- [ ] Preserve inserted field values in the returned document.
- [ ] Apply model default values before insert if this is not already handled by core storage code.
- [ ] Apply per-field input transforms before insert if this is not already handled by core storage code.
- [ ] Support create-time `select` output behavior if OpenAuth's storage contract includes it.
- [ ] Test create inserts into the expected collection.
- [ ] Test create passes session when a transaction is active.
- [ ] Test create returns the inserted document with public `id`.
- [ ] Test create returns transformed FK values consistently with the core output contract.
- [ ] Test default values are applied on create.
- [ ] Test per-field input transforms are applied on create.
- [ ] Test create with nullable foreign-key `null`.
- [ ] Test create supports array fields.
- [ ] Test create supports JSON fields according to the chosen JSON behavior.

### Task 9: Find One Operation

**Upstream reference:** `findOne({ model, where, select, join })`

- [ ] Build an aggregation pipeline starting with `$match`.
- [ ] Use empty `$match` when no `where` is provided.
- [ ] Add join lookup stages when joins are requested.
- [ ] Add projection when `select` is provided.
- [ ] Include joined collections in projection when both `select` and `join` are provided.
- [ ] Append `$limit: 1`.
- [ ] Return `None` when aggregation returns no documents.
- [ ] Return the first document after output transformations.
- [ ] Pass the active session when inside a transaction.
- [ ] Support custom model names in collection lookup.
- [ ] Support custom field names in `where`, `select`, projection, and joins.
- [ ] Support additional fields defined by plugins/options.
- [ ] Support date fields.
- [ ] Support one-to-one joins returning object/null.
- [ ] Support one-to-many joins returning arrays.
- [ ] Support multiple joins at once.
- [ ] Support backwards joins where the base model owns the foreign key.
- [ ] Return null for missing base model even when joins are requested.
- [ ] Test find-one with no filter.
- [ ] Test find-one with `where`.
- [ ] Test find-one with `select`.
- [ ] Test find-one with `join`.
- [ ] Test find-one returns `None` for empty results.
- [ ] Test find-one limits result to one document.
- [ ] Test find-one converts BSON UUID `_id` to string output.
- [ ] Test find-one with custom model name.
- [ ] Test find-one with custom field name.
- [ ] Test find-one with additional fields.
- [ ] Test find-one with date fields.
- [ ] Test find-one one-to-one joins.
- [ ] Test find-one one-to-many joins.
- [ ] Test find-one multiple joins.
- [ ] Test find-one backwards joins.
- [ ] Test find-one missing joined one-to-one record returns `null`.
- [ ] Test find-one missing one-to-many records returns an empty array.

### Task 10: Find Many Operation

**Upstream reference:** `findMany({ model, where, limit, select, offset, sortBy, join })`

- [ ] Build an aggregation pipeline starting with `$match`.
- [ ] Use empty `$match` when no `where` is provided.
- [ ] Add join lookup stages when joins are requested.
- [ ] Add projection when `select` is non-empty.
- [ ] Include joined collections in projection when both `select` and `join` are provided.
- [ ] Add `$sort` when `sort_by` is provided.
- [ ] Convert ascending sort to `1`.
- [ ] Convert descending sort to `-1`.
- [ ] Add `$skip` when `offset` is provided.
- [ ] Add `$limit` when `limit` is provided.
- [ ] Apply default `find_many` limit from database options when caller does not provide a limit.
- [ ] Preserve upstream default `findMany` limit of `100` unless OpenAuth intentionally chooses and documents another default.
- [ ] Return all documents after output transformations.
- [ ] Pass the active session when inside a transaction.
- [ ] Test find-many with no filter.
- [ ] Test find-many with `where`.
- [ ] Test find-many with `select`.
- [ ] Test find-many with empty select does not add projection.
- [ ] Test find-many with sort ascending and descending.
- [ ] Test find-many with offset.
- [ ] Test find-many with limit.
- [ ] Test find-many with join.
- [ ] Test find-many default limit.
- [ ] Test find-many returns empty array for no base records.
- [ ] Test find-many with date fields.
- [ ] Test find-many with custom model name.
- [ ] Test find-many with custom field name.
- [ ] Test find-many with additional fields.
- [ ] Test find-many with one-to-one joins.
- [ ] Test find-many with one-to-many joins.
- [ ] Test find-many with multiple joins.
- [ ] Test find-many backwards joins.
- [ ] Test find-many joined missing one-to-one record returns `null`.
- [ ] Test find-many joined missing one-to-many records returns empty arrays.

### Task 11: Join Pipeline Behavior

**Upstream reference:** join handling inside `findOne` and `findMany`

- [ ] Resolve local join field through the field-name mapper.
- [ ] Resolve foreign join field through the joined model field-name mapper.
- [ ] Convert local `id` join field to `_id`.
- [ ] Convert foreign `id` join field to `_id`.
- [ ] Use `$lookup` simple syntax when no join limit is needed.
- [ ] Use `$lookup` pipeline syntax with `let`, `$expr`, and `$limit` when a non-unique relation has a configured limit.
- [ ] In `findOne`, determine one-to-one flattening from the joined model foreign field unique constraint.
- [ ] In `findMany`, determine one-to-one flattening from field attributes and join relation metadata.
- [ ] Apply default join limit from database options when limit pipeline is enabled and no explicit limit is provided.
- [ ] Preserve upstream default join limit of `100`.
- [ ] Respect the upstream/native join gate: Mongo join pipelines are used only when the storage/core layer enables native/experimental joins; otherwise fallback joins are performed by the core adapter layer.
- [ ] Implement or delegate fallback join behavior: query joined models separately and attach results after base output transformation.
- [ ] Ensure required join fields are included in `select` so joins can still be resolved when callers select only some base fields.
- [ ] Reject joins when no FK exists between base and joined model.
- [ ] Reject joins when multiple FKs exist and the relation is ambiguous.
- [ ] Use `$unwind` with `preserveNullAndEmptyArrays: true` for unique/one-to-one joins.
- [ ] Keep one-to-many joins as arrays without unwind.
- [ ] Test simple `$lookup` with public `id` fields mapped to `_id`.
- [ ] Test pipeline `$lookup` with explicit limit.
- [ ] Test default join limit of `100`.
- [ ] Test unique/one-to-one join adds unwind.
- [ ] Test one-to-many join does not add unwind.
- [ ] Test joined model projection is preserved when select is used.
- [ ] Test native/experimental joins enabled path.
- [ ] Test fallback joins disabled/native joins off path if OpenAuth has both paths.
- [ ] Test required selected join field is included internally without leaking unexpected fields in output.
- [ ] Test no-FK join error.
- [ ] Test ambiguous multi-FK join error.
- [ ] Test limited joins in `findOne`.
- [ ] Test limited joins in `findMany`.
- [ ] Test complex limited joins with multiple relations.

### Task 12: Count Operation

**Upstream reference:** `count({ model, where })`

- [ ] Build an aggregation pipeline with `$match` then `$count: "total"`.
- [ ] Use empty `$match` when no `where` is provided.
- [ ] Return `0` when aggregation returns no rows.
- [ ] Return `total` when present.
- [ ] Default missing `total` to `0`.
- [ ] Pass the active session when inside a transaction.
- [ ] Test count without filter.
- [ ] Test count with filter.
- [ ] Test count returns zero for empty aggregation result.
- [ ] Test count returns zero for missing `total`.

### Task 13: Update Operation

**Upstream reference:** `update({ model, where, update })`

- [ ] Convert `where` into a MongoDB filter.
- [ ] Run `find_one_and_update` with `$set` update values.
- [ ] Request the document after update.
- [ ] Preserve metadata handling equivalent to upstream `includeResultMetadata: true` where relevant to the Rust driver.
- [ ] Return `None` when no document is updated.
- [ ] Return the updated document after output transformations.
- [ ] Pass the active session when inside a transaction.
- [ ] Apply per-field update transforms and `on_update` fields if this is not already handled by core storage code.
- [ ] Support updating multiple fields including fields used in the `where` clause.
- [ ] Support `where` clauses using `null` values.
- [ ] Test update builds the expected filter.
- [ ] Test update uses `$set`.
- [ ] Test update returns the updated document.
- [ ] Test update returns `None` when no document is matched.
- [ ] Test update does not generate a new ID for absent ID fields.
- [ ] Test update returns a record when updating a field used in the `where` clause.
- [ ] Test update handles multiple updated fields including a `where` field.
- [ ] Test update works when the updated field is not in the `where` clause.
- [ ] Test update with `null` in the `where` clause.

### Task 14: Update Many Operation

**Upstream reference:** `updateMany({ model, where, update })`

- [ ] Convert `where` into a MongoDB filter.
- [ ] Run `update_many` with `$set` update values.
- [ ] Return the modified document count.
- [ ] Pass the active session when inside a transaction.
- [ ] Allow empty `where` to update all records if OpenAuth's storage contract permits this, matching upstream adapter test behavior.
- [ ] Test update-many builds the expected filter.
- [ ] Test update-many uses `$set`.
- [ ] Test update-many returns modified count.
- [ ] Test update-many with empty `where`.
- [ ] Test update-many with multiple `where` conditions.

### Task 15: Delete Operation

**Upstream reference:** `delete({ model, where })`

- [ ] Convert `where` into a MongoDB filter.
- [ ] Run `delete_one`.
- [ ] Return unit/success when MongoDB accepts the operation.
- [ ] Pass the active session when inside a transaction.
- [ ] Test delete builds the expected filter.
- [ ] Test delete calls `delete_one`.
- [ ] Test delete passes session when a transaction is active.
- [ ] Test delete by non-unique field.
- [ ] Test delete does not throw when no record matches.

### Task 16: Delete Many Operation

**Upstream reference:** `deleteMany({ model, where })`

- [ ] Convert `where` into a MongoDB filter.
- [ ] Run `delete_many`.
- [ ] Return deleted document count.
- [ ] Pass the active session when inside a transaction.
- [ ] Test delete-many builds the expected filter.
- [ ] Test delete-many calls `delete_many`.
- [ ] Test delete-many returns deleted count.
- [ ] Test delete-many with numeric field values.
- [ ] Test delete-many with boolean field values.
- [ ] Test delete-many with escaped starts-with regex.
- [ ] Test delete-many with escaped ends-with regex.
- [ ] Test delete-many with escaped contains regex.

### Task 17: Transaction Support

**Upstream reference:** transaction config in adapter factory

- [ ] Support adapter-level transaction wrapper when a MongoDB client is configured and transactions are enabled.
- [ ] Start a MongoDB client session.
- [ ] Start a transaction before executing the callback/body.
- [ ] Build a session-bound adapter for operations inside the transaction.
- [ ] Commit the transaction when the callback/body succeeds.
- [ ] Abort the transaction when the callback/body returns an error.
- [ ] Always end the session after commit or abort.
- [ ] Fall back to non-transactional execution when no client is configured.
- [ ] Return the callback/body result after commit.
- [ ] Propagate callback/body errors after abort.
- [ ] Test success path starts session, starts transaction, commits, and ends session.
- [ ] Test error path starts session, starts transaction, aborts, ends session, and propagates error.
- [ ] Test no-client path executes without a transaction.
- [ ] Test explicit `transaction = false` executes without a transaction even when a client exists.

### Task 18: Upstream Test Parity

**Upstream reference:** `src/mongodb-adapter.test.ts`

- [ ] Port the adapter construction test.
- [ ] Port UUID `_id` storage test.
- [ ] Port UUID FK storage test.
- [ ] Port default ObjectId `_id` storage test.
- [ ] Port BSON UUID output-to-string test.
- [ ] Port or mirror Better Auth adapter `normal` test-suite coverage at scenario level: create, find-one, find-many, update, update-many, delete, delete-many, count, custom names, additional fields, default values, selects, joins, operators, null comparisons, arrays, and JSON.
- [ ] Port or mirror Better Auth adapter `case-insensitive` suite: insensitive `eq`, sensitive mismatch, insensitive `findMany`, `ne`, `in`, `not_in`, `contains`, `starts_with`, `ends_with`, `count`, `update`, and `deleteMany`.
- [ ] Port or mirror Better Auth adapter `joins` suite with native joins enabled.
- [ ] Port or mirror Better Auth adapter `transactions` suite rollback behavior.
- [ ] Port or mirror Better Auth adapter `uuid` suite.
- [ ] Do not port Better Auth `number-id` success expectations as Mongo requirements; instead assert numeric/serial IDs are unsupported because this adapter sets `supportsNumericIds: false`.
- [ ] Add missing Rust-side tests for query builders because upstream has query builder functions without direct tests.
- [ ] Add missing Rust-side tests for all CRUD operations because upstream only lightly covers construction and ID conversion.
- [ ] Add missing Rust-side tests for transaction behavior because upstream does not test transaction success/failure paths.
- [ ] Add missing Rust-side tests for join pipelines because upstream behavior is non-trivial and not directly covered.

### Task 19: Documentation

**Upstream reference:** `README.md`, config comments in `MongoDBAdapterConfig`

- [ ] Document how to construct the MongoDB adapter.
- [ ] Document required MongoDB database/client inputs.
- [ ] Document default ObjectId behavior.
- [ ] Document BSON UUID strategy behavior.
- [ ] Document custom ID strategy behavior.
- [ ] Document transaction defaults.
- [ ] Document the standalone MongoDB transaction caveat and how to disable transactions.
- [ ] Document collection naming and pluralization behavior.
- [ ] Document that numeric IDs are unsupported.
- [ ] Document native joins versus fallback joins if OpenAuth exposes both paths.
- [ ] Document JSON storage behavior, especially if OpenAuth improves on upstream by storing BSON documents instead of stringified JSON.
- [ ] Document `force_allow_id` or the equivalent explicit create-ID override if exposed.
- [ ] Document that this is server-side adapter behavior only.

### Task 20: Dependency and Feature-Gate Review

**Upstream reference:** `package.json`

- [ ] Propose the MongoDB Rust driver dependency before adding it.
- [ ] Confirm BSON UUID support in the selected MongoDB/BSON crate version.
- [ ] Map upstream `mongodb` dependency functionality to Rust equivalents: `Db`/database handle, `MongoClient`, `ClientSession`, `ObjectId`, BSON UUID, aggregate pipelines, `find_one_and_update`, `update_many`, `delete_one`, `delete_many`, transactions.
- [ ] Treat upstream `@better-auth/core` as behavioral dependency for adapter factory behavior: schema lookup, field/model mapping, ID generation policy, default values, transforms, debug logs, telemetry spans, joins, and transaction fallback.
- [ ] Note that upstream `@better-auth/utils` is declared in `package.json` but not imported by this package source; do not add a Rust dependency for it unless another inspected upstream file requires it.
- [ ] Treat `vitest`, `tsdown`, and `typescript` as test/build-only dependencies with no runtime Rust behavior to port.
- [ ] Gate the adapter behind a feature or separate crate so MongoDB is not forced into the core path.
- [ ] Keep MongoDB-specific types out of the core public API unless the adapter crate owns them.
- [ ] Verify dependency maintenance, documentation, and compatibility with async runtime choices.

### Task 21: Core Adapter Factory Behavior Dependency

**Upstream reference:** `@better-auth/core/db/adapter`

- [ ] Decide whether OpenAuth core storage code or the Mongo adapter owns transform input behavior.
- [ ] Decide whether OpenAuth core storage code or the Mongo adapter owns transform output behavior.
- [ ] Apply default field values on create.
- [ ] Do not apply default values when stored `null` values are read back.
- [ ] Apply per-field input transforms before persistence.
- [ ] Apply per-field output transforms after reads.
- [ ] Convert string dates to dates at API/storage boundaries when needed by OpenAuth's contract.
- [ ] Preserve date values natively for MongoDB unless an intentional compatibility layer requires string conversion.
- [ ] Preserve booleans natively for MongoDB.
- [ ] Preserve arrays natively for MongoDB.
- [ ] Either match upstream `supportsJSON: false` stringification/parsing or intentionally improve MongoDB JSON support with native BSON documents and tests.
- [ ] Convert public selected fields after output transformation.
- [ ] Ensure output IDs are always strings even when internal MongoDB values are ObjectId or BSON UUID.
- [ ] Support additional schema fields from plugins/options.
- [ ] Support field `on_update` behavior if OpenAuth schema supports it.
- [ ] Test default values.
- [ ] Test read-back of explicit `null` values.
- [ ] Test input transforms.
- [ ] Test output transforms.
- [ ] Test date handling.
- [ ] Test boolean handling.
- [ ] Test array handling.
- [ ] Test JSON handling.
- [ ] Test additional plugin/option fields.
- [ ] Test `on_update` behavior if supported.

### Task 22: Model and Field Name Resolution

**Upstream reference:** `get-model-name.ts`, `get-default-model-name.ts`, `get-field-name.ts`, `get-default-field-name.ts`, `get-field-attributes.ts`

- [ ] Resolve default model names from custom configured model names.
- [ ] Resolve custom model names to MongoDB collection names.
- [ ] Apply `use_plural` by appending `s` to collection names.
- [ ] Accept already-plural model names when resolving defaults under `use_plural`.
- [ ] Resolve default field names from custom configured field names.
- [ ] Resolve custom field names to MongoDB document keys.
- [ ] Treat public `id` and Mongo `_id` as the same logical field when resolving defaults.
- [ ] Return typed errors for unknown models.
- [ ] Return typed errors for unknown fields.
- [ ] Test default model lookup.
- [ ] Test custom model lookup.
- [ ] Test plural model lookup.
- [ ] Test default field lookup.
- [ ] Test custom field lookup.
- [ ] Test `id`/`_id` field lookup.
- [ ] Test unknown model error.
- [ ] Test unknown field error.

### Task 23: Debug Logging and Telemetry

**Upstream reference:** `createAdapterFactory` debug logging and `withSpan` calls

- [ ] Support adapter debug logging disabled by default.
- [ ] Support debug logging enabled globally.
- [ ] Support method-specific debug logging for create, update, update-many, find-one, find-many, delete, delete-many, and count if OpenAuth exposes method-level flags.
- [ ] Support conditional debug logging if OpenAuth exposes a log predicate.
- [ ] Support test-captured debug logs only if OpenAuth adapter tests need this behavior.
- [ ] Include adapter name in debug logs.
- [ ] Include operation input, parsed input, database result, and parsed result phases where useful.
- [ ] Emit storage telemetry spans around create, update, update-many, find-one, find-many, delete, delete-many, and count if OpenAuth telemetry supports DB spans.
- [ ] Include DB operation name and collection/model name on telemetry spans.
- [ ] Test debug logs disabled.
- [ ] Test method-specific debug logs if supported.
- [ ] Test telemetry span metadata if OpenAuth telemetry has a test harness.

### Task 24: Endpoint and OpenAPI Non-Scope

**Upstream reference:** package-wide search for endpoints/routes/openapi

- [ ] Confirm the Mongo adapter package has no `createAuthEndpoint` usage.
- [ ] Confirm the Mongo adapter package has no routes/endpoints.
- [ ] Confirm the Mongo adapter package has no OpenAPI metadata.
- [ ] Keep endpoint behavior in auth/API packages, not in the Mongo adapter crate.
- [ ] If future OpenAuth adapter registration needs docs metadata, keep it separate from runtime storage behavior.

### Task 25: Intentional Improvements Over Upstream

**Upstream reference:** whole package plus Rust/OpenAuth conventions

- [ ] Prefer typed Rust errors over stringly `MongoAdapterError` codes.
- [ ] Prefer typed query/filter builders over ad hoc document construction where it improves safety without hiding MongoDB semantics.
- [ ] Prefer native BSON document storage for JSON fields if this fits OpenAuth's storage contract better than upstream stringification.
- [ ] Prefer explicit config enums for ID strategy instead of overloaded string/function values.
- [ ] Prefer integration tests with real MongoDB for transaction behavior, because transaction correctness depends on MongoDB deployment mode.
- [ ] Keep unit tests for pure filter/pipeline/ID builders so most behavior does not require MongoDB.
- [ ] Keep modules small and single-purpose: config, errors, IDs, regex helpers, filters, pipelines, transforms, transactions, adapter operations, and tests by behavior area.

## Completion Criteria

- [ ] Every server-side operation in `mongodb-adapter.ts` has a Rust equivalent or an intentional documented deviation.
- [ ] Every query helper in `query-builders.ts` has a Rust equivalent or an intentional documented deviation.
- [ ] Every upstream test scenario in `mongodb-adapter.test.ts` has a Rust test.
- [ ] Rust tests cover behavior upstream does not directly test: where conversion, joins, transactions, update/delete/count, and regex escaping.
- [ ] Rust tests cover behavior delegated by upstream to `createAdapterFactory`: model/field mapping, default values, transforms, `forceAllowId`, default find-many limit, debug/telemetry if supported, and fallback joins if supported.
- [ ] No TypeScript-only packaging/build behavior is ported into Rust.
- [ ] No endpoint/OpenAPI behavior is added for this adapter package.
- [ ] MongoDB adapter code remains outside the core path unless explicitly feature-gated.

## Self-Review

- [ ] Spec coverage checked against all upstream package files listed above.
- [ ] No checklist item depends on inspecting the current OpenAuth implementation state.
- [ ] No browser-only or TypeScript-only behavior is included as a Rust server requirement.
- [ ] No endpoint, `createAuthEndpoint`, or OpenAPI behavior is included because upstream `mongo-adapter` does not define any.
- [ ] All behavior-bearing upstream functions are represented: `mongodbAdapter`, `MongoDBAdapterConfig`, `MongoAdapterError`, ID conversion helpers, `serializeID`, `convertWhereClause`, CRUD methods, transaction wrapper, output/input transforms, custom ID generator, and regex helpers.
- [ ] All behavior-bearing upstream dependencies are represented: adapter factory transforms, model/field resolution, ID field generation, debug logs, telemetry spans, native/fallback joins, default find-many limit, and adapter test suites.
- [ ] Tests are tracked at scenario level, not at overly granular assertion level.
