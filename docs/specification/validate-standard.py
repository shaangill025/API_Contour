#!/usr/bin/env python3
"""Run local specification checks before JSON Schema/OpenAPI standard validation."""
import importlib.util
import copy
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
schema_v2 = local.load(ROOT / "contracts/batch-v2.schema.json")
Draft202012Validator.check_schema(schema_v2)
validator_v2 = Draft202012Validator(schema_v2, format_checker=FormatChecker())
fixtures_v2 = local.load(ROOT / "fixtures/batches-v2.json")
for fixture in fixtures_v2:
    try:
        validator_v2.validate(fixture["body"])
        local.semantic_check_v2(fixture["body"])
        actual = "accept"
    except (ValueError, ValidationError):
        actual = "reject"
    local.require(actual == fixture["expected"], "standard V2 fixture outcome: " + fixture["id"])
causal_schema = local.load(ROOT / "contracts/causal-event-batch.schema.json")
Draft202012Validator.check_schema(causal_schema)
causal_validator = Draft202012Validator(causal_schema)
for fixture in local.load(ROOT / "fixtures/causal-events.json"):
    try:
        causal_validator.validate(fixture["body"])
        local.causal_semantic_check(fixture["body"])
        actual = "accept"
    except (ValueError, ValidationError):
        actual = "reject"
    local.require(actual == fixture["expected"], "standard causal fixture outcome: " + fixture["id"])
# Standard schema validation operates on already decoded JSON; duplicate raw
# keys are rejected by the loader/codec, not by JSON Schema itself.
v2_valid = next(row["body"] for row in fixtures_v2 if row["id"] == "valid_claim")
for change in ("digest", "witness_extra", "wrapper_extra"):
    candidate = copy.deepcopy(v2_valid)
    wrapper = candidate["records"][0]
    if change == "digest": wrapper["origin_witness"]["leaf_sha256"] = "g" * 64
    elif change == "witness_extra": wrapper["origin_witness"]["verified"] = True
    else: wrapper["verified"] = True
    local.require(not validator_v2.is_valid(candidate), "standard V2 rejection regression: " + change)
duplicate = copy.deepcopy(v2_valid)
duplicate["records"].append(copy.deepcopy(duplicate["records"][0]))
validator_v2.validate(duplicate)
try:
    local.semantic_check_v2(duplicate)
except ValueError:
    pass
else:
    raise ValueError("V2 duplicate record ID semantic regression")
legacy = next(row["body"] for row in fixtures if row["id"] == "valid_structure")
validator.validate(legacy)
legacy_extra = copy.deepcopy(legacy)
legacy_extra["records"][0]["origin_witness"] = {"kind":"unattributed"}
local.require(not validator.is_valid(legacy_extra), "standard V1 witness rejection regression")
api_path = ROOT / "contracts/platform.openapi.json"
validate(local.load(api_path), base_uri=api_path.as_uri())
print(json.dumps({"status": "PASS", "json_schema": "2020-12", "openapi": "3.1",
                  "batch_fixtures": len(fixtures), "batch_v2_fixtures": len(fixtures_v2),
                  "product_acceptance": "NOT_RUN"}))
