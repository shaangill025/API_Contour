#!/usr/bin/env python3
"""Run local specification checks before JSON Schema/OpenAPI standard validation."""
import importlib.util
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from openapi_spec_validator import validate

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("local_spec", ROOT / "validate.py")
local = importlib.util.module_from_spec(spec)
spec.loader.exec_module(local)
# Reject remote references and inconsistent local contracts before standard loading.
local.main()
schema = local.load(ROOT / "contracts/batch.schema.json")
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema, format_checker=FormatChecker())
fixtures = local.load(ROOT / "fixtures/batches.json")
for fixture in fixtures:
    try:
        validator.validate(fixture["body"])
        local.semantic_check(fixture["body"])
        actual = "accept"
    except (ValueError, ValidationError):
        actual = "reject"
    local.require(actual == fixture["expected"], "standard fixture outcome: " + fixture["id"])
api_path = ROOT / "contracts/platform.openapi.json"
validate(local.load(api_path), base_uri=api_path.as_uri())
print(json.dumps({"status": "PASS", "json_schema": "2020-12", "openapi": "3.1",
                  "batch_fixtures": len(fixtures), "product_acceptance": "NOT_RUN"}))
