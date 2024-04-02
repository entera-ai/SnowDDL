from snowddl.blueprint import (
    DatabaseIdent,
    DatabaseBlueprint,
    SchemaRoleBlueprint,
    SchemaIdent,
    SchemaBlueprint,
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

        for schema in self.config.get_blueprints_by_type(SchemaBlueprint).values():
            if schema.schema_roles == False:
                # don't generate any roles for this schema
                continue
            
            # if schema_roles attribute is not specified, create all roles by default
            if schema.schema_roles == []:
                blueprints.append(self.get_blueprint_owner_role(schema))
                blueprints.append(self.get_blueprint_read_role(schema))
                blueprints.append(self.get_blueprint_write_role(schema))
            # otherwise, create only specified roles
            else:
                for schema_role in schema.schema_roles:
                    if schema_role.lower() == "owner":
                        blueprints.append(self.get_blueprint_owner_role(schema))
                    if schema_role.lower() == "read":
                        blueprints.append(self.get_blueprint_read_role(schema))
                    if schema_role.lower() == "write":
                        blueprints.append(self.get_blueprint_write_role(schema))

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

        source_db_blueprint = list(self.config.get_blueprints_by_type_and_pattern(
            DatabaseBlueprint, 
            source_db_name
        ).values())[0]

        cloned_database_identifiers = [
            DatabaseIdent(source_db_blueprint.full_name.env_prefix, db_name)
            for db_name in source_db_blueprint.copy_schema_role_grants_to_db_clones
        ]
        database_identifiers.extend(cloned_database_identifiers)

        return database_identifiers

    def get_blueprint_owner_role(self, schema_bp: SchemaBlueprint):
        grants = []
        future_grants = []

        database_identifiers = self.gather_db_identifiers_for_schema_role_grants(schema_bp)

        create_object_types = [
            ObjectType.FILE_FORMAT,
            ObjectType.FUNCTION,
            ObjectType.PROCEDURE,
            ObjectType.TABLE,
            ObjectType.VIEW,
        ]

        ownership_object_types = [
            ObjectType.EXTERNAL_TABLE,
            ObjectType.FILE_FORMAT,
            ObjectType.FUNCTION,
            ObjectType.MATERIALIZED_VIEW,
            ObjectType.PIPE,
            ObjectType.PROCEDURE,
            ObjectType.SEQUENCE,
            ObjectType.STREAM,
            ObjectType.TABLE,
            ObjectType.TASK,
            ObjectType.VIEW,
        ]

        privileges_map = {
            ObjectType.DYNAMIC_TABLE: ["MONITOR", "OPERATE", "SELECT"],
            ObjectType.STAGE: ["READ", "WRITE", "USAGE"],
        }

        for database_identifier in database_identifiers:
            grants.append(
                Grant(
                    privilege="USAGE",
                    on=ObjectType.DATABASE,
                    name=database_identifier,
                )
            )

            schema_identifier = SchemaIdent(
                schema_bp.full_name.env_prefix,
                database_identifier, 
                schema_bp.full_name.schema
            )

            grants.append(
                Grant(
                    privilege="USAGE",
                    on=ObjectType.SCHEMA,
                    name=schema_identifier,
                )
            )

            for object_type in create_object_types:
                grants.append(
                    Grant(
                        privilege=f"CREATE {object_type.singular}",
                        on=ObjectType.SCHEMA,
                        name=schema_identifier,
                    )
                )

            for object_type in ownership_object_types:
                future_grants.append(
                    FutureGrant(
                        privilege="OWNERSHIP",
                        on=object_type,
                        name=schema_identifier,
                    )
                )

            for object_type, privileges in privileges_map.items():
                for privilege in privileges:
                    future_grants.append(
                        FutureGrant(
                            privilege=privilege,
                            on=object_type,
                            name=schema_identifier,
                        )
                    )

        depends_on = set()

        for additional_grant in schema_bp.owner_additional_grants:
            # Dependency on another schema role
            if additional_grant.on == ObjectType.ROLE and str(additional_grant.name).endswith(self.get_role_suffix()):
                depends_on.add(additional_grant.name)

            grants.append(additional_grant)

        bp = SchemaRoleBlueprint(
            full_name=build_role_ident(
                self.config.env_prefix, schema_bp.full_name.database, schema_bp.full_name.schema, "OWNER", self.get_role_suffix()
            ),
            grants=grants,
            future_grants=future_grants,
            depends_on=depends_on,
        )

        return bp

    def get_blueprint_read_role(self, schema_bp: SchemaBlueprint):
        grants = []
        future_grants = []

        database_identifiers = self.gather_db_identifiers_for_schema_role_grants(schema_bp)

        privileges_map = {
            ObjectType.DYNAMIC_TABLE: ["SELECT"],
            ObjectType.EXTERNAL_TABLE: ["SELECT", "REFERENCES"],
            ObjectType.FILE_FORMAT: ["USAGE"],
            ObjectType.FUNCTION: ["USAGE"],
            ObjectType.MATERIALIZED_VIEW: ["SELECT", "REFERENCES"],
            ObjectType.PROCEDURE: ["USAGE"],
            ObjectType.STAGE: ["READ", "USAGE"],
            ObjectType.STREAM: ["SELECT"],
            ObjectType.TABLE: ["SELECT", "REFERENCES"],
            ObjectType.VIEW: ["SELECT", "REFERENCES"],
        }

        for database_identifier in database_identifiers:
            grants.append(
                Grant(
                    privilege="USAGE",
                    on=ObjectType.DATABASE,
                    name=database_identifier,
                )
            )

            schema_identifier = SchemaIdent(
                schema_bp.full_name.env_prefix,
                database_identifier, 
                schema_bp.full_name.schema
            )

            grants.append(
                Grant(
                    privilege="USAGE",
                    on=ObjectType.SCHEMA,
                    name=schema_identifier,
                )
            )

            for object_type, privileges in privileges_map.items():
                for privilege in privileges:
                    future_grants.append(
                        FutureGrant(
                            privilege=privilege,
                            on=object_type,
                            name=schema_identifier,
                        )
                    )

        bp = SchemaRoleBlueprint(
            full_name=build_role_ident(
                self.config.env_prefix, schema_bp.full_name.database, schema_bp.full_name.schema, "READ", self.get_role_suffix()
            ),
            grants=grants,
            future_grants=future_grants,
        )

        return bp

    def get_blueprint_write_role(self, schema_bp: SchemaBlueprint):
        grants = []
        future_grants = []

        database_identifiers = self.gather_db_identifiers_for_schema_role_grants(schema_bp)

        privileges_map = {
            ObjectType.STAGE: ["READ", "WRITE"],
            ObjectType.SEQUENCE: ["USAGE"],
            ObjectType.TABLE: ["INSERT", "UPDATE", "DELETE", "TRUNCATE"],
        }

        for database_identifier in database_identifiers:
            grants.append(
                Grant(
                    privilege="USAGE",
                    on=ObjectType.DATABASE,
                    name=database_identifier,
                )
            )

            schema_identifier = SchemaIdent(
                schema_bp.full_name.env_prefix,
                database_identifier, 
                schema_bp.full_name.schema
            )

            grants.append(
                Grant(
                    privilege="USAGE",
                    on=ObjectType.SCHEMA,
                    name=schema_identifier,
                )
            )

            for object_type, privileges in privileges_map.items():
                for privilege in privileges:
                    future_grants.append(
                        FutureGrant(
                            privilege=privilege,
                            on=object_type,
                            name=schema_identifier,
                        )
                    )

        bp = SchemaRoleBlueprint(
            full_name=build_role_ident(
                self.config.env_prefix, schema_bp.full_name.database, schema_bp.full_name.schema, "WRITE", self.get_role_suffix()
            ),
            grants=grants,
            future_grants=future_grants,
        )

        return bp
