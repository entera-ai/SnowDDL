from typing import List, Dict, Union

from snowddl.blueprint import (
    DatabaseIdent,
    FutureGrant,
    Grant,
    RoleBlueprint,
    DatabaseBlueprint,
    SchemaIdent,
    SchemaBlueprint,
    SchemaObjectIdent,
    build_role_ident,
    IdentPattern,
)
from snowddl.resolver.abc_role_resolver import AbstractRoleResolver, ObjectType


class SchemaAccessRoleResolver(AbstractRoleResolver):
    def get_role_suffix(self):
        return self.config.SCHEMA_ACCESS_ROLE_SUFFIX

    def get_blueprints(self):
        blueprints = []

        for schema_bp in self.config.get_blueprints_by_type(SchemaBlueprint).values():
            schema_permission_model = self.config.get_permission_model(schema_bp.permission_model)

            if schema_bp.schema_roles == False:
                # don't generate any roles for this schema
                continue

            schema_bp.schema_roles = [role.lower() for role in schema_bp.schema_roles]
            # generate some or all schema roles using permission model
            # if schema_roles[list[str]] is non-empty, generate just those roles
            # if schema roles is an empty list, generate all roles
            if schema_permission_model.ruleset.create_schema_owner_role and (
                "owner" in schema_bp.schema_roles or schema_bp.schema_roles == []
            ):
                blueprints.append(self.get_blueprint_owner_role(schema_bp))
            if schema_permission_model.ruleset.create_schema_write_role and (
                "write" in schema_bp.schema_roles or schema_bp.schema_roles == []
            ):
                blueprints.append(self.get_blueprint_write_role(schema_bp))
            if schema_permission_model.ruleset.create_schema_read_role and (
                "read" in schema_bp.schema_roles or schema_bp.schema_roles == []
            ):
                blueprints.append(self.get_blueprint_read_role(schema_bp))

        return {str(bp.full_name): bp for bp in blueprints}

    def gather_db_identifiers_for_schema_role_grants(self, schema_bp: SchemaBlueprint):
        """
        The copy_schema_role_grants_to_db_clones attribute of the DatabaseBlueprint class
        allows for specifying a list of database clones which should inherit the privileges
        granted to a particular schema role. For example, if the copy_schema_role_grants_to_db_clones
        attribute for the ANALYTICS database is set to ["ANALYTICS_CLONE1", "ANALYTICS_CLONE2"],
        then all default grants applied to it's schema roles also get duplexed to the specified
        clones. For instance, if the ANALYTICS__<schema>__OWNER__S_ROLE has USAGE on ANALYTICS,
        then it also gets USAGE on ANALYTICS_CLONE1 and ANALYTICS_CLONE2.

        This method is a helper to gather the list of database identifiers to which schema role
        grants should be applied in the get_blueprint_*_role() methods. This list will be a union
        of the database identifier specified by the schema_bp argument, and the database identifiers
        found in the copy_schema_role_grants_to_db_clones attribute for that schema's DatabaseBlueprint.
        """
        database_identifiers = []

        source_db_name = schema_bp.full_name.database
        source_db_identifier = DatabaseIdent(schema_bp.full_name.env_prefix, source_db_name)
        database_identifiers.append(source_db_identifier)

        source_db_blueprint = list(
            self.config.get_blueprints_by_type_and_pattern(DatabaseBlueprint, IdentPattern(source_db_name)).values()
        )[0]

        cloned_database_identifiers = [
            DatabaseIdent(source_db_blueprint.full_name.env_prefix, db_name)
            for db_name in source_db_blueprint.copy_schema_role_grants_to_db_clones
        ]
        database_identifiers.extend(cloned_database_identifiers)

        return database_identifiers

    def get_blueprint_owner_role(self, schema_bp: SchemaBlueprint):
        grants = []
        account_grants = []
        future_grants = []
        depends_on = set()

        schema_permission_model = self.config.get_permission_model(schema_bp.permission_model)

        database_identifiers = self.gather_db_identifiers_for_schema_role_grants(schema_bp)

        for database_identifier in database_identifiers:
            grants.append(
                Grant(
                    privilege="USAGE",
                    on=ObjectType.DATABASE,
                    name=database_identifier,
                )
            )

            schema_identifier = SchemaIdent(schema_bp.full_name.env_prefix, database_identifier, schema_bp.full_name.schema)

            grants.append(
                Grant(
                    privilege="USAGE",
                    on=ObjectType.SCHEMA,
                    name=schema_identifier,
                )
            )

            # Iceberg-related grants
            if schema_bp.external_volume:
                grants.append(
                    Grant(
                        privilege="USAGE",
                        on=ObjectType.VOLUME,
                        name=schema_bp.external_volume,
                    )
                )

            if schema_bp.catalog:
                grants.append(
                    Grant(
                        privilege="USAGE",
                        on=ObjectType.INTEGRATION,
                        name=schema_bp.catalog,
                    )
                )

            # Create grants
            for model_create_grant in schema_permission_model.owner_create_grants:
                grants.append(
                    Grant(
                        privilege=f"CREATE {model_create_grant.on.singular}",
                        on=ObjectType.SCHEMA,
                        name=schema_identifier,
                    )
                )

            # Future grants on SCHEMA level
            for model_future_grant in schema_permission_model.owner_future_grants:
                future_grants.append(
                    FutureGrant(
                        privilege=model_future_grant.privilege,
                        on_future=model_future_grant.on,
                        in_parent=ObjectType.SCHEMA,
                        name=schema_identifier,
                    )
                )

        # Owner-specific grants
        for database_name_pattern in schema_bp.owner_database_write:
            grants.extend(self.build_database_role_grants(database_name_pattern, self.config.WRITE_ROLE_TYPE))

        for database_name_pattern in schema_bp.owner_database_read:
            grants.extend(self.build_database_role_grants(database_name_pattern, self.config.READ_ROLE_TYPE))

        for schema_name_pattern in schema_bp.owner_schema_write:
            grants.extend(self.build_schema_role_grants(schema_name_pattern, self.config.WRITE_ROLE_TYPE))

        for schema_name_pattern in schema_bp.owner_schema_read:
            grants.extend(self.build_schema_role_grants(schema_name_pattern, self.config.READ_ROLE_TYPE))

        for integration_name in schema_bp.owner_integration_usage:
            grants.append(self.build_integration_grant(integration_name))

        for share_name in schema_bp.owner_share_read:
            grants.append(self.build_share_read_grant(share_name))

        for warehouse_name in schema_bp.owner_warehouse_usage:
            grants.append(self.build_warehouse_role_grant(warehouse_name, self.config.USAGE_ROLE_TYPE))

        for account_grant in schema_bp.owner_account_grants:
            account_grants.append(account_grant)

        for global_role_name in schema_bp.owner_global_roles:
            grants.append(self.build_global_role_grant(global_role_name))

        # Add explicit dependencies on other schema roles
        for g in grants:
            if g.on == ObjectType.ROLE and str(g.name).endswith(self.get_role_suffix()):
                depends_on.add(g.name)

        bp = RoleBlueprint(
            full_name=build_role_ident(
                self.config.env_prefix,
                schema_bp.full_name.database,
                schema_bp.full_name.schema,
                self.config.OWNER_ROLE_TYPE,
                self.get_role_suffix(),
            ),
            grants=grants,
            account_grants=account_grants,
            future_grants=future_grants,
            depends_on=depends_on,
        )

        return bp

    def get_blueprint_read_role(self, schema_bp: SchemaBlueprint):
        grants = []
        future_grants = []

        schema_permission_model = self.config.get_permission_model(schema_bp.permission_model)

        database_identifiers = self.gather_db_identifiers_for_schema_role_grants(schema_bp)

        for database_identifier in database_identifiers:
            grants.append(
                Grant(
                    privilege="USAGE",
                    on=ObjectType.DATABASE,
                    name=database_identifier,
                )
            )
            schema_identifier = SchemaIdent(schema_bp.full_name.env_prefix, database_identifier, schema_bp.full_name.schema)
            grants.append(
                Grant(
                    privilege="USAGE",
                    on=ObjectType.SCHEMA,
                    name=schema_identifier,
                )
            )
            for model_future_grant in schema_permission_model.read_future_grants:
                future_grants.append(
                    FutureGrant(
                        privilege=model_future_grant.privilege,
                        on_future=model_future_grant.on,
                        in_parent=ObjectType.SCHEMA,
                        name=schema_identifier,
                    )
                )

        bp = RoleBlueprint(
            full_name=build_role_ident(
                self.config.env_prefix,
                schema_bp.full_name.database,
                schema_bp.full_name.schema,
                self.config.READ_ROLE_TYPE,
                self.get_role_suffix(),
            ),
            grants=grants,
            future_grants=future_grants,
        )

        return bp

    def get_blueprint_write_role(self, schema_bp: SchemaBlueprint):
        grants = []
        future_grants = []

        schema_permission_model = self.config.get_permission_model(schema_bp.permission_model)

        database_identifiers = self.gather_db_identifiers_for_schema_role_grants(schema_bp)

        for database_identifier in database_identifiers:
            grants.append(
                Grant(
                    privilege="USAGE",
                    on=ObjectType.DATABASE,
                    name=database_identifier,
                )
            )
            schema_identifier = SchemaIdent(schema_bp.full_name.env_prefix, database_identifier, schema_bp.full_name.schema)
            grants.append(
                Grant(
                    privilege="USAGE",
                    on=ObjectType.SCHEMA,
                    name=schema_identifier,
                )
            )
            for model_future_grant in schema_permission_model.write_future_grants:
                future_grants.append(
                    FutureGrant(
                        privilege=model_future_grant.privilege,
                        on_future=model_future_grant.on,
                        in_parent=ObjectType.SCHEMA,
                        name=schema_identifier,
                    )
                )

        bp = RoleBlueprint(
            full_name=build_role_ident(
                self.config.env_prefix,
                schema_bp.full_name.database,
                schema_bp.full_name.schema,
                self.config.WRITE_ROLE_TYPE,
                self.get_role_suffix(),
            ),
            grants=grants,
            future_grants=future_grants,
        )

        return bp

    def grant_to_future_grant(self, grant: Grant):
        if not grant.on.is_future_grant_supported:
            return None

        if isinstance(grant.name, SchemaObjectIdent):
            return FutureGrant(
                privilege=grant.privilege,
                on_future=grant.on,
                in_parent=ObjectType.SCHEMA,
                name=grant.name.schema_full_name,
            )

        return None
