# Changelog

## [0.27.2] - 2024-05-09

- Restore `USAGE` future grant on `STAGE` object type for default permission model. `READ` grant is still not enough to access external stages properly.

## [0.27.1] - 2024-05-08

- Grant schema OWNERSHIP privilege to DATABASE OWNER role. Unfortunately, it seems to be the only way to allow external tools to DROP schemas.

## [0.27.0] - 2024-05-06

This is a major update to permissions and SnowDDL internals, which introduces some breaking changes. [Read more about it](https://docs.snowddl.com/breaking-changes-log/0.27.0-may-2024).

- Introduced a concept of "Permission model", which allows to customize create grants and future grants. Previously these grants were hardcoded.
- Permission model can operate using default "schema owner" ruleset or new "database owner" ruleset, which is designed specifically for external ETL tools which try to create their own schemas, like Fivetran and Airbyte.
- Changed `OWNERSHIP` of the following object types to schema owner role: `ALERT`, `DYNAMIC_TABLE`, `EVENT_TABLE`, `STAGE`. Previously these object types were owned by SnowDDL admin role.
- Added new parameters for `SCHEMA` related to  permission management: `owner_warehouse_usage`, `owner_account_grants`, `owner_global_roles`.
- Added new parameters for `DATABASE` related to permission management: `owner_integration_usage`, `owner_warehouse_usage`, `owner_account_grants`, `owner_global_roles`.
- Added new parameters for `BUSINESS_ROLE` related to permission management: `database_owner`, `database_write`, `database_read`.
- Renamed `TECH_ROLE` to `TECHNICAL_ROLE`. Old configs with `tech_roles` parameter are still supported, no need to change anything.
- Introduced a concept of "account grants" - special type of grants on entire account. The main difference is lack of grant "name".
- Added an option to set custom `account_grants` for `TECHNICAL_ROLE`.
- Reworked internals regarding future grants. Future grants are now automatically applied to existing objects on creation. Future grants on `DATABASE` are now supported. Previously it was only supported on `SCHEMA`.
- Reworked check for exotic table types in `TABLE` resolver. Now it should no longer fail when Snowflake keeps adding and removing columns about exotic table types in `SHOW TABLES` output.
- When trying to revoke `OWNERSHIP`, it will be transferred to SnowDDL admin role instead of skipping this change altogether.
- Fixed future grants for `ALERT` object type.
- Fixed blueprint class reference for `HYBRID_TABLE`.
- Added better error messages when trying to convert `TRANSIENT` `DATABASE` or `SCHEMA` to non-`TRANSIENT`, or vice versa.

## [0.26.0] - 2024-04-16

- Introduced the concept of "intention cache". Initially it will be used to store and check intentions to drop or replace parent objects, so child objects can be properly resolved during "plan" action. For example, `DROP TABLE` command implicitly drops all table constraints, so there is no need to generate SQL commands to drop constraints.
- Reverted explicit setting to destroy schemas in SingleDB. It should be handled automatically by "intention cache" checks.
- Reworked `HYBRID_TABLE` to apply all constraints on table creation. Wait for Snowflake to resolve `FOREIGN KEY` issues with Hybrid Tables.

## [0.25.3] - 2024-04-11

- Added explicit setting to destroy schemas. Use it in SingleDB mode only. Do not attempt to destroy schemas in normal mode.
- Set `TARGET_DB` automatic placeholder earlier, but only if `--target-db` argument was specified.

## [0.25.2] - 2024-04-03

- Added CLI options `--refresh-stage-encryption` and `--refresh-secrets` to SingleDB mode.

## [0.25.1] - 2024-03-21

- Prevented SingleDB mode from asking for `--destroy-without-prefix` CLI option which is not possible to set on "destroy" action.
- Ensured schemas are correctly "destroyed" even when `DatabaseResolver` is not present in resolver sequence. Most schema objects are still being ignored.

## [0.25.0] - 2024-03-20

- Added browser-based SSO authentication (thanks to Joseph Niblo).

## [0.24.0] - 2024-03-11

- Implemented `HYBRID_TABLE` object type using short hash.
- Switched `depends_on` implementation from list to set, which should help to avoid deduplication problem entirely.
- Added SQL comment with specific replace reasons when replace table is required.
- Adjusted replace table logic to avoid unnecessary type casting when data type was not changed.
- Added some tests for `HYBRID_TABLE`.

## [0.23.2] - 2024-03-08

- Skipped all new fancy table types while working on normal `TABLE` in resolver, converter and during cloning.
- Added explicit `MONITOR`, `OPERATE` and `SELECT` privileges for `DYNAMIC_TABLE` for schema owner role.
- Added explicit `SELECT` privilege for `DYNAMIC_TABLE` for schema read role.
- Updated handling of metadata for optional arguments in `FUNCTION` and `PROCEDURE`. Snowflake replaced brackets-syntax `[, NUMBER]` with more traditional `, DEFAULT NUMBER`.

You may have to run SnowDDL with flag `--refresh-future-grants` to apply new privileges to existing dynamic tables.

## [0.23.1] - 2024-01-17

- Added `owner_integration_usage` parameter for `SCHEMA`. It grants usage privilege to schema owner role on integrations pre-configured outside SnowDDL.

## [0.23.0] - 2024-01-16

- Added remaining parameters for `TASK`.
- Added `is_ordered` for `SEQUENCE`.
- Added converter for `TASKS` (thanks to Osborne Hardison).
- Adjusted converter for `TABLE` to ignore event tables.
- Fixed issue with ALTER for `STAGE` objects trying to apply `REFRESH_ON_CREATE` to existing objects, which is not allowed.

## [0.22.1] - 2024-01-06

- Added `error_notification` for `PIPE`.
- Added tests for `PIPE`.

## [0.22.0] - 2023-11-23

- Introduced `NETWORK RULE`, `SECRET`, `EXTERNAL ACCESS INTEGRATION` object types.
- Added `EXTERNAL_ACCESS_INTEGRATIOS` and `SECRETS` parameters for functions and procedures.
- Added ability to set `default` for function and procedure arguments.
- Fixed issue with event tables being dropped while processing normal tables.
- Implemented "owner" check via `SHOW GRANTS` for `NETWORK POLICY` and `EXTERNAL ACCESS INTEGRATION`. "Owner" column is normally not available for these objects types.
- Added `--env-admin-role` CLI option.

## [0.21.0] - 2023-11-01

- Introduced custom value for application option (`SnowDDL <version>`) while opening Snowflake connection. Now it should be possible to find sessions created by SnowDDL using `SESSIONS` system view.
- Added `--query-tag` CLI option to set custom `QUERY_TAG` session parameter.
- Fixed pydantic deprecation warning related to `__fields__`.
- Added explicit `.close()` call for Snowflake connection after execution of CLI commands. It should help to terminate SnowDDL sessions earlier, regardless of `CLIENT_SESSION_KEEP_ALIVE` parameter.

## [0.20.1] - 2023-10-20

- Added additional debug logs for `VIEW` resolver in attempt to diagnose rare unnecessary re-creation problem.

## [0.20.0] - 2023-10-13

- Replaced blueprint dataclasses with `pydantic` V2 models. Dataclasses are no longer used.
- Introduced a lot of default parameter values for the majority of blueprints and related objects. It should make the custom code operating on config and blueprints more clear. It will also prevent this code from breaking when new optional parameters are added to blueprints.
- Introduced `black` for code formatting. Reformatted entire codebase.
- Introduced `ruff` for code linting. Fixed or explicitly skipped ruff warnings across the entire codebase.
- Introduced the ability to dynamically add custom blueprints and adjust existing blueprints by placing Python modules in special config directory `__custom`.
- Database names starting with `__` (double underscore) will now be ignored. It is necessary to support more special config sub-directories in future.

## [0.18.2] - 2023-08-16

- When comparing grants, run `REVOKE` commands prior to `GRANT` commands. It should help to resolve issues with `OWNERSHIP` future grant, which should be revoked before a new `OWNERSHIP` grant can be added.

## [0.18.1] - 2023-07-26

- Ignore grants for object types which are currently not supported by SnowDDL.

## [0.18.0] - 2023-07-18

- Added initial implementation of table cloning while using `--env-prefix` argument.
- Fixed issue with `STAGE` re-applying `directory` parameter on every run.
- Fixed issue with `DYNAMIC_TABLE` re-applying `target_lag` parameter on every run.
- Fixed missing `change_tracking` parameter for some `DYNAMIC_TABLE` tests.

## [0.17.1] - 2023-07-16

- Improved handling of `PRIMARY_KEY` when column list is being changed.

## [0.17.0] - 2023-07-10

- Implemented `DYNAMIC_TABLE` object type.
- Implemented `EVENT_TABLE` object type (only with `change_tracking` parameter).

## [0.16.1] - 2023-06-08

- Do not remove accounts from `OUTBOUND_SHARE` if `accounts` parameter was not set in config. Outbound shares without explicitly defined accounts are managed by Snowflake Marketplace.

## [0.16.0] - 2023-05-08

- Implemented custom YAML tag `!include`, which allows to load specific config parameters from external files. It helps to maintain proper syntax highlight for SQL snippets (such as `VIEW` text) and bodies of Java / Scala / Python UDFs.
- Added more tests for `PROCEDURE` object type.

## [0.15.0] - 2023-05-03

- Switched from packaging via legacy `setup.py` to `pyproject.toml` and `setup.cfg`.

## [0.14.4] - 2023-04-22

- Grant `CREATE FILE FORMAT` privilege for OWNER schema roles. It should help to handle common use case when external tools try to create a `FILE_FORMAT` object before running `COPY INTO` command.

## [0.14.3] - 2023-03-08

- Move `STRICT` and `IMMUTABLE` before `RUNTIME_VERSION` in SQL generated for object types `FUNCTION` and `PROCEDURE`.

## [0.14.2] - 2023-02-26

- Added `is_memoizable` for `FUNCTION` object type.
- Added tests for `FUNCTION` object type.
- Starting slash `/` in `STAGE FILE` path is now optional.
- Runtime version for `FUNCTION` and `PROCEDURE` in YAML config can now be defined either as `number` or as `string`. Previously it was only defined as string, which caused confusion for numeric versions, like Python "3.8".

## [0.14.1] - 2023-02-23

- Added `__hash__` implementation for `Ident` objects. It allows usage of such objects as keys for dictionaries.

## [0.14.0] - 2023-02-12

- Implemented `ALERT` object type.
- Added better error message for missing `text` in YAML config for `VIEW` object type.

## [0.13.0] - 2023-01-24

- Completely reworked `STAGE` object type resolver. Now it checks actual property values and does not rely on short hash anymore. `STAGE` objects will be re-created only when absolutely necessary. ALTER will be applied for the majority of changes.
- Introduced CLI option `--refresh-stage-encryption` to re-apply encryption parameters for each external `STAGE`. Normally it is not possible to compare config encryption parameters with existing parameters in Snowflake.
- Introduced a few "safe" alters for `TABLE` object type: (1) add new column, (2) change comment on table, (3) change comment on specific column. Previously all alters for `TABLE` were unsafe.
- `ROLE` resolver will no longer try to revoke `OWNERSHIP` grant on objects. This grant can only be transferred.
- `ROLE` resolver will now revoke `WRITE` permission on `STAGES` before trying to revoke `READ` permission.

## [0.12.3] - 2022-12-25

- Fixed incorrect condition checking `comment` property for `WAREHOUSE` object type, which caused every warehouse to be re-created on every run.
- `FILE_FORMAT` object type is now properly replaced when `type` was changed. Other changes are still applied using `alter file format` command.
- Added tests for `PROCEDURE` and `FILE_FORMAT` object types.

## [0.12.2] - 2022-12-04

- Fixed incorrect order of parameters when resolving `PROCEDURE` with both `comment` and `is_execute_as_caller`.
- Added protection from `FUNCTION` and `PROCEDURE` arguments with TIMESTAMP-like type and non-default precision. Snowflake bug, case 00444370.

Tests for UDFs and procedures are expected to be added in the next version.

## [0.12.1] - 2022-11-29

- Fixed a bug with `session_params` being ignored for `USER` object type. Added additional checks to tests.

## [0.12.0] - 2022-11-23

- (!breaking change!) Object types `NETWORK_POLICY` and `RESOURCE_MONITOR` now use env prefix, similar to other account-level objects. Previously env prefix was ignored for these object types.
- (!breaking change!) Object types `NETWORK_POLICY` and `RESOURCE_MONITOR` are now dropped during `destroy` action as long as `--apply-network-policy` and `--apply-resource-monitor` options are present.
- Added `global_resource_monitor` parameter for `WAREHOUSE` object type. Original `resource_monitor` now refers to monitor defined in config and managed by SnowDDL. New `global_resource_monitor` refers to monitor managed outside SnowDDL.
- User with `ACCOUNTADMIN` privileges is now required to run tests. It is not possible to test `RESOURCE_MONITOR` object type otherwise.
- Fixed a bug with `warehouse_params` not being applied for `WAREHOUSE` object type.
- Fixed a bug with `WAREHOUSE` parameters not being properly updated in specific edge cases.
- Added tests for `WAREHOUSE`, `NETWORK_POLICY`, `RESOURCE_MONITOR` object types.

## [0.11.0] - 2022-11-16

- Implement query acceleration and object parameters for `WAREHOUSE` object type.
- Prevent suggestion of individual schema object drops if an entire schema was dropped.
- Add automatic placeholder `TARGET_DB` for SingleDB mode. It holds full identifier of target database.
- Add Snowflake account name and region to context object and logs.
- Add special conversion logic for `IDENTITY` columns of object type `TABLE`. Such columns are converted into `SEQUENCE` objects automatically.
- Rework naming of tests and objects in tests. It should help to streamline and speed up implementation of new tests.
- Add complete SQL file with all commands required to set up a new Snowflake test account from scratch.

## [0.10.0] - 2022-10-19

- Add `is_transient` and `retention_time` for `TABLE` object type config.
- Add `is_transient` to `TABLE` object type converter.
- Implement advanced SEARCH OPTIMIZATION on specific columns. NB: VARIANT column paths are currently not supported due to high complexity of parsing `target` column from output of `DESC SEARCH OPTIMIZATION` command.

## [0.9.9] - 2022-10-13

- Strip trailing spaces from each line of view text during `VIEW` object type conversion. It prevents formatting issues described in [pyyaml#411 issue](https://github.com/yaml/pyyaml/issues/411).

## [0.9.8] - 2022-10-11

- Add `collate` support for `TABLE` object type conversion.

## [0.9.7] - 2022-10-05

- Try to fix markdown formatting on PyPi.
- Enable converter for object type `VIEW` (currently not documented, work in progress).

## [0.9.6] - 2022-09-09

- Prevent `USER_ROLE` resolver from dropping grants other than `ROLE` grants. User roles may accumulate random grants during normal operation from temporary tables, temporary stages, manually created objects in schemas not managed by SnowDDL.
- Change testing Snowflake account once again.

## [0.9.5] - 2022-08-29

- Implement missing `comment` parameter for `USER` object type.
- Add more tests.

## [0.9.4] - 2022-08-23

- Added new supported data type `GEOMETRY` (in addition to existing `GEOGRAPHY`).
- Added env variable `SNOWFLAKE_ENV_PREFIX` to specify `--env-prefix` without explicitly mentioning it in CLI command.
- Added a workaround for Snowflake bug, which creates a grant for hidden MATERIALIZED VIEW when search optimization is enabled for a table.
- Completely reworked an approach to tests. Now tests are executed in 3 steps, each step consists of "snowddl apply" followed by pytest execution. Now it should be much easier to add and maintain a large number of test.

## [0.9.3] - 2022-08-19

- Expose internal query builder `SnowDDLQueryBuilder` as public class. Now it can be used in external projects.
- Minor internal changes in SQL formatter.

## [0.9.2] - 2022-08-15

- Implemented proper ALTER for `FILE_FORMAT`, fixed a bug when SnowDDL tried to re-create `FILE_FORMAT` which already exists. Also, `EXTERNAL_TABLE` will not lose association with `FILE_FORMAT` after ALTER.
- Object types `EXTERNAL_FUNCTION`, `EXTERNAL_TABLE`, `FUNCTION`, `PROCEDURE` are now correctly resolved as REPLACE instead of ALTER, when object was actually replaced by `CREATE OR REPLACE ...` command.

## [0.9.1] - 2022-08-13

- Fixed incorrect encoding while opening files on Windows machines. Now it is explicitly set to `utf-8`.

## [0.9.0] - 2022-08-01

- (!breaking change!) Parameter `after` of `TASK` object type is now array of strings to support newly released [DAG-feature](https://docs.snowflake.com/en/user-guide/tasks-intro.html#dag-of-tasks). Previously it was a basic string.
- Fixed a major bug with dependency resolution, when allocated full names were not preserved between cycles properly.
- Allowed `$` (dollar sign) character in identifiers.
- Added basic `expression` parameter to `TABLE` columns, as an experimental feature. Currently, it requires fully resolved and normalized SQL expression. Otherwise, SnowDDL will fail to perform expression comparison and suggest re-creating a table on every run.
- Added `--include-databases` and `--ignore-ownership` options for `snowddl-convert` entry-point.

## [0.8.0] - 2022-07-28

- Implemented `OUTBOUND_SHARE` object type.
- Implemented test version of `INBOUND_SHARE` object type, which is currently disabled during normal execution.
- It is now possible to specify `grants` for `TECH_ROLE` and `OUTBOUND_SHARE` using [Unix-style wildcards](https://docs.python.org/3/library/fnmatch.html).
- Fixed typo in `EXTERNAL_FUNCTION` blueprint parameter `api_integration`.
- Fixed type in `TECH_ROLE` JSON-schema used to validate YAML config.
- Improved patter-matching for specific `ROLE`-types. Now it should work properly with multi-letter role-suffixes.

## [0.7.4] - 2022-07-13

- `destroy` CLI action now adds option `--apply-unsafe` automatically. Option `--destroy-without-prefix` should still provide a sufficient protection from accidentally destroying everything on production.
- Dropping object types `ROLE`, `EXTERNAL TABLE`, `STAGE` is now considered "unsafe". Dropping `ROLE` prior to dropping other objects causes re-assignment of OWNERSHIP. Dropping `EXTERNAL TABLE` causes loss of associated meta-data (e.g. files, partitions), which cannot be restored easily. Dropping `INTERNAL STAGE` destroys all files in that stage.

## [0.7.3] - 2022-07-12

- Use special exit code `8` when any errors occurred inside resolvers or converters. Previously it was returned as exit code `0`.
- If user role was dropped manually, it will now be re-created and re-granted to corresponding user automatically.

## [0.7.2] - 2022-07-01

- Fixed `default_sequence` for table columns not being converted when using `singledb` mode.
- Fixed DEFAULT value not being applied properly when adding new columns using `ALTER TABLE ... ADD COLUMN`.
- Switched to another Snowflake Trial account.

## [0.7.1] - 2022-06-29

- Ignore `TEMPORARY STAGES` created by another sessions. Such stages should not appear in `SHOW STAGES` output, but they do.

## [0.7.0] - 2022-06-27

- Added `runtime_version`, `imports`, `packages`, `handler` for `PROCEDURE` object type.
- Added ability to set multiple columns for `returns` of `PROCEDURE` object type, now it is possible to define `RETURNS TABLE (...)`.
- Added initial `collate` support for `TABLE` columns.

## [0.6.1] - 2022-06-15

- Added `packages` for `FUNCTION` object type. Now it should be possible to use fully utilize Snowpark, Python and Java UDFs.
- `SnowDDLFormatter` is now exposed as public object, if you want to use it for something other than SnowDDL.

## [0.6.0] - 2022-06-05

- Implemented first version of `snowddl-singledb` entry-point. It is a simplified version of SnowDDL to manage schemas and objects in a single database only. Account-level objects, roles and grants are NOT resolved in this mode. Please check the documentation for more details.
- Schemas will no longer produce `DROP SCHEMA ...` SQL commands during `destroy` action without `--apply-unsafe` flag, similar to schema objects. All schemas are dropped implicitly after execution of `DROP DATABASE` anyway.
- Added `database_full_name` property for `SchemaIdent` and `SchemaObjectIdent` objects to simplify access to corresponding `DatabaseIdent` object.
- Replaced `argparse.Namespace` with basic `dict` for handling of CLI arguments. It helps to streamline access to specific arguments which may not be defined in other entry-points.

## [0.5.5] - 2022-05-31

- Fix missing grants for `schema_owner`, `schema_write`, `schema_read` business role options without wildcards.

## [0.5.4] - 2022-05-31

- Speed up SnowDDL execution by loading grants and future grants of existing roles in parallel.

## [0.5.3] - 2022-05-30

- Added a basic wildcard option while setting `schema_owner`, `schema_write`, `schema_read` options for business roles to match "all schemas in database". For example: `snowddl_db.*`. At least one schema matching wildcard condition should exist in config.

It is useful for managing generic script roles when new schemas are added and / or removed frequently.

## [0.5.2] - 2022-05-30

- Identifier objects were completely reworked. Now every identifier type has its own class with every part being named.
- Simplified blueprint objects. Removed `database`, `schema`, `name` fields from schema object blueprints. All this information is available as parts of `full_name`.
- Moved complex logic for "building" identifiers into dedicated module `ident_builder`.
- Performed initial preparation and testing for "singledb" entry point, which will be added in the next version.

## [0.5.1] - 2022-05-25

- Rework internal architecture of entry-points for SnowDDL CLI interface. Now it will be much easier to add new entry-points and to partially re-use existing entry-points in your own code.

## [0.5.0] - 2022-05-24

- Added parameters `login_name`, `display_name` for `USER` object type.
- Added argument `--placeholder-values` for CLI interface. It allows passing custom placeholder values in JSON format without creation of temporary file for `--placeholder-path`.

## [0.4.10] - 2022-05-12

- Fix grants not being revoked properly for object types which do not support FUTURE GRANTs.

## [0.4.9] - 2022-05-09

- Added parameters `partition_type` and `table_format` for `EXTERNAL TABLE` object type.
- `location.file_format` is now required parameter for `EXTERNAL TABLE`.

## [0.4.8] - 2022-05-06

- `OWNERSHIP` on `STAGE` objects are no longer granted to schema OWNER role via FUTURE GRANT. All stages will be owned directly by admin role instead. Otherwise, it is not possible to use external stages without explicit grant of `USAGE` on `STORAGE_INTEGRATION` object to the current role or schema owner role, which is not desirable.

In order to fix `OWNERSHIP` on stages, you may execute the following expression for each affected schema with stages and restart SnowDDL to re-apply other grants:

```
GRANT OWNERSHIP ON ALL STAGES IN SCHEMA <database>.<schema> TO ROLE <snowddl_admin_role> REVOKE CURRENT GRANTS;
```

## [0.4.7] - 2022-05-02

- Revert to session to original `WAREHOUSE` after execution of `WarehouseResolver` if necessary. Snowflake implicitly switches to newly created `WAREHOUSE` after successful CREATE statement, which is not desirable for the rest of the session.

## [0.4.6] - 2022-04-11

- `SHOW PROCEDURES` was replaced with `SHOW USER PROCEDURES`, in line with Snowflake release notes.
- Added `owner_schema_read`, `owner_schema_write` parameters for schema. If specified, grants READ or WRITE roles from other schemas to the OWNER role of the current schema. It helps to make objects in other schemas accessible for `VIEWS` and `PROCEDURES`. Normally OWNER role can only access objects in the current schema.
- Dependency management was enabled for schema roles.

## [0.4.5] - 2022-04-02

- MD5 markers which are automatically generated for `STAGE FILES` are now uploaded directly using `file_stream` option for `.execute()` command of Snowflake Python Connector. Temporary directory is no longer used.
- `file_stream` option is now available for `.execute_safe_ddl()`, `.execute_unsafe_ddl()`. It might be used in future for more advanced operations with contents of internal stages.

## [0.4.4] - 2022-03-27

- Added technical placeholder `env_prefix` which is always available for YAML configs. It should be used to access objects in other databases when specifying `VIEW` definitions (`${{ env_prefix }}db_name.schema_name.object_name`). Objects in the same database can still be accessed without specifying database name (`schema_name.object_name`).
- Fetching list of existing `STAGE FILES` no longer fails if stage exists in blueprints, but does not exist in Snowflake account.
- Resolver for `STAGE FILES` is now skipped when "destroy" action is being called. All files are destroyed automatically when stage is deleted.

## [0.4.3] - 2022-03-17

- Replaced explicit `format_exc()` calls during config validation with modern `TracebackException.from_exception().format()` API. Pre-formatted error messages will no longer be stored in `SnowDDLConfig`, but rather be formatted on demand using `Exception` object only.
- Fixed typos in some JSON schemas.
- Simplified the way how `.resolved_objects` property is being stored for resolvers. Now it is a basic `dict` with object full name as key and `ResolveResult` enum as value.

## [0.4.2] - 2022-03-12

- Added more tests for `TABLE` and `VIEW` object types.
- Improved project description.

## [0.4.1] - 2022-03-02

- Implemented `EXTERNAL FUNCTION` object type.
- Added validation for YAML config file names for object types supporting overloading.
- Re-create "invalid" `EXTERNAL TABLES` automatically.
- Switched test account to AWS.

## [0.4.0] - 2022-02-22

- Reworked parsers. Now most exceptions raised in parsers will no longer interrupt the program, but will be stored and reported later. Each reported exception now has a proper traceback and pointer to file which most likely caused the problem.
- Implemented [placeholders](https://docs.snowddl.com/basic/yaml-placeholders) in YAML configs.
- Config path is now fully resolved prior to execution, which should help to produce consistent logs regardless of symlinks or cwd.
- Added support for `STAGE FILE` object type, which is intended mainly for packages for Snowpark functions.
- Added support for Snowpark function options: `IMPORTS`, `HANDLER`, `RUNTIME_VERSION`.

## [0.3.1] - 2022-02-18

- Use `SYSTEM$BOOTSTRAP_DATA_REQUEST` to detect edition of Snowflake account.
- Drop admin role with prefix when calling `destroy` action with `--env-prefix`. Current role of connection reverts to original role without prefix.

## [0.3.0] - 2022-02-17

- Added `NETWORK_POLICY` and `RESOURCE_MONITOR` to list of supported object types.

## [0.2.1] - 2022-02-16

- Added `is_sandbox` for `DATABASE` object type, in addition to `SCHEMA` object type.
- Dump empty `params.yaml` files for `DATABASE` and `SCHEMA` during conversion to preserve empty schemas. Empty directories cannot be pushed to Git.
- Added basic safety checks for `env_prefix`. It cannot contain double underscore `__` and it cannot end with underscore `_`.

## [0.2.0] - 2022-02-15

- Added optional `-r` (ROLE) and `-w` (WAREHOUSE) arguments for SnowDDL CLI interface.
- Added basic converters from existing `DATABASE`, `SCHEMA`, `TABLE`, `SEQUENCE` objects to SnowDDL YAML configs.
- Removed future grants from `SCHEMA ROLE (WRITE)` for `VIEW` object type.
- "Getting Started Test" workflow now runs each config version twice to detect possible changes being missed on first run.
- Fixed bug with `comment` and `default` not being applied to `TABLE` columns in some cases.
- Fixed bug with short hashes being used as byte-strings instead of properly decoded pure `ascii` representations.
- Fixed bug with other alters being applied to columns dropped from `TABLE` in some cases.
- Fixed bug with table column comment not being applied immediately on `ADD COLUMN`.
- Fixed bug with role comment not being applied immediately on `CREATE ROLE`.
- Reworked the way how `comment` is being applied to `VIEW` object type. Snowflake implicitly modifies view `text` in `SHOW VIEWS` if it contains a `comment` during `CREATE VIEW`, which breaks view checks on subsequent runs.
- If `VIEW` was replaced, the resolve result is now `REPLACE` instead of `ALTER`.

## [0.1.1] - 2022-02-11

- Fixed typing annotations for `List` and `Dict` to make it compatible with Python 3.7.

## [0.1.0] - 2022-02-10

- SnowDDL was released under an open source license.
