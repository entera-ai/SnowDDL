from snowddl.blueprint import (
    DatabaseIdent,
    DatabaseBlueprint,
    SchemaIdent,
    SchemaRoleBlueprint,
    SchemaBlueprint,
    SchemaObjectIdent,
    Grant,
    FutureGrant,
    build_role_ident,
)
from snowddl.resolver.abc_role_resolver import AbstractRoleResolver, ObjectType


class SchemaRoleResolver(AbstractRoleResolver):
    def get_role_suffix(self):
        return self.config.SCHEMA_ROLE_SUFFIX

    def get_blueprints(self):
        blueprints = []

        for schema_bp in self.config.get_blueprints_by_type(SchemaBlueprint).values():
            if schema_bp.schema_roles == False:
                # don't generate any roles for this schema
                continue
            elif schema_bp.schema_roles == []:
                # if schema_roles attribute is not specified, create all roles by default
                if schema_bp.permission_model.ruleset.create_schema_owner_role:
                    blueprints.append(self.get_blueprint_owner_role(schema_bp))
                if schema_bp.permission_model.ruleset.create_schema_write_role:
                    blueprints.append(self.get_blueprint_write_role(schema_bp))
                if schema_bp.permission_model.ruleset.create_schema_read_role:
                    blueprints.append(self.get_blueprint_read_role(schema_bp))
            else:
                # otherwise, create only specific roles
                for schema_role in schema_bp.schema_roles:
                    if schema_role.lower() == "owner":
                        blueprints.append(self.get_blueprint_owner_role(schema_bp))
                    if schema_role.lower() == "read":
                        blueprints.append(self.get_blueprint_read_role(schema_bp))
                    if schema_role.lower() == "write":
                        blueprints.append(self.get_blueprint_write_role(schema_bp))

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

        source_db_blueprint = list(self.config.get_blueprints_by_type_and_pattern(DatabaseBlueprint, source_db_name).values())[0]

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
            for model_create_grant in schema_bp.permission_model.owner_create_grants:
                grants.append(
                    Grant(
                        privilege=f"CREATE {model_create_grant.on.singular}",
                        on=ObjectType.SCHEMA,
                        name=schema_identifier,
                    )
                )
            for model_future_grant in schema_bp.permission_model.owner_future_grants:
                future_grants.append(
                    FutureGrant(
                        privilege=model_future_grant.privilege,
                        on_future=model_future_grant.on,
                        in_parent=ObjectType.SCHEMA,
                        name=schema_identifier,
                    )
                )

        depends_on = set()

        for additional_grant in schema_bp.owner_additional_grants:
            grants.append(additional_grant)

            # Dependency on another schema role
            if additional_grant.on == ObjectType.ROLE and str(additional_grant.name).endswith(self.get_role_suffix()):
                depends_on.add(additional_grant.name)

        for additional_account_grant in schema_bp.owner_additional_account_grants:
            account_grants.append(additional_account_grant)

        bp = SchemaRoleBlueprint(
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
            for model_future_grant in schema_bp.permission_model.read_future_grants:
                future_grants.append(
                    FutureGrant(
                        privilege=model_future_grant.privilege,
                        on_future=model_future_grant.on,
                        in_parent=ObjectType.SCHEMA,
                        name=schema_identifier,
                    )
                )

        bp = SchemaRoleBlueprint(
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
            for model_future_grant in schema_bp.permission_model.write_future_grants:
                future_grants.append(
                    FutureGrant(
                        privilege=model_future_grant.privilege,
                        on_future=model_future_grant.on,
                        in_parent=ObjectType.SCHEMA,
                        name=schema_identifier,
                    )
                )

        bp = SchemaRoleBlueprint(
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
