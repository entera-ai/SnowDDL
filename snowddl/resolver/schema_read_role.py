from snowddl.blueprint import (
    DatabaseIdent,
    SchemaIdent,
    FutureGrant,
    Grant,
    RoleBlueprint,
    SchemaBlueprint,
    SchemaObjectIdent,
    build_role_ident,
)
from snowddl.resolver.abc_role_resolver import AbstractRoleResolver, ObjectType


class SchemaReadRoleResolver(AbstractRoleResolver):
    def get_role_suffix(self):
        return self.config.SCHEMA_ACCESS_ROLE_SUFFIX

    def get_role_type(self):
        return self.config.READ_ROLE_TYPE

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
            if schema_permission_model.ruleset.create_schema_read_role and (
                "read" in schema_bp.schema_roles or schema_bp.schema_roles == []
            ):
                blueprints.append(self.get_blueprint_read_role(schema_bp))

        return {str(bp.full_name): bp for bp in blueprints}

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
