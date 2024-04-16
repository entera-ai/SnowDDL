from snowddl.blueprint import DatabaseBlueprint, DatabaseIdent
from snowddl.parser.abc_parser import AbstractParser


# fmt: off
database_json_schema = {
    "type": "object",
    "properties": {
        "is_transient": {
            "type": "boolean"
        },
        "retention_time": {
            "type": "integer"
        },
        "is_sandbox": {
            "type": "boolean"
        },
        "comment": {
            "type": "string"
        },
        "copy_schema_role_grants_to_db_clones": {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
        "schema_roles": {
            "anyOf": [
                {
                    "type": "object",
                    "properties": {
                        "owner": {
                            "type": "object",
                            "properties": {
                                "create": {
                                    "type": "array",
                                    "items": {
                                        "type": "string"
                                    }
                                },
                                "ownership": {
                                    "type": "array",
                                    "items": {
                                        "type": "string"
                                    }
                                },
                                "privileges": {
                                    "type": "object",
                                    "propertyNames": {
                                        "enum": ["DYNAMIC TABLES", "STAGES"]
                                    },
                                }
                            }
                        },
                        "read": {
                            "type": "object",
                            "properties": {
                                "privileges": {
                                    "type": "object",
                                    "propertyNames": {
                                        "enum": ["DYNAMIC TABLES", "EXTERNAL TABLES", "FILE FORMATS", "FUNCTIONS", "MATERIALIZED VIEWS", "PROCEDURES", "STAGES", "STREAMS", "TABLES", "VIEWS"]
                                    },
                                }
                            }
                        },
                        "write": {
                            "type": "object",
                            "properties": {
                                "privileges": {
                                    "type": "object",
                                    "propertyNames": {
                                        "enum": ["STAGES", "SEQUENCES", "TABLES"]
                                    },
                                }
                            }
                        },
                    }
                },
                {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                {
                    "type": "boolean"
                }
            ],
        },
    },
    "additionalProperties": False
}
# fmt: on


class DatabaseParser(AbstractParser):
    def load_blueprints(self):
        for database_path in self.base_path.iterdir():
            if not database_path.is_dir():
                continue

            # Skip special sub-directories
            if database_path.name.startswith("__"):
                continue

            params = self.parse_single_file(database_path / "params.yaml", database_json_schema)

            bp = DatabaseBlueprint(
                full_name=DatabaseIdent(self.env_prefix, database_path.name),
                is_transient=params.get("is_transient", False),
                retention_time=params.get("retention_time", None),
                is_sandbox=params.get("is_sandbox", False),
                comment=params.get("comment", None),
                copy_schema_role_grants_to_db_clones=params.get("copy_schema_role_grants_to_db_clones", [])
            )

            self.config.add_blueprint(bp)
