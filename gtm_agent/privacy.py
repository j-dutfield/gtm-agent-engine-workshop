import json
import re


SENSITIVE_FIELDS = frozenset({
    "billing_qualification",
    "tax_id",
    "date_of_birth",
    "card_on_file",
    "credit_check_ref",
})

_SERIALIZED_BILLING_PATTERN = re.compile(
    r"[\"']?billing_qualification[\"']?\s*:\s*\{[^{}]*\},?",
    re.IGNORECASE,
)
_SERIALIZED_FIELD_PATTERN = re.compile(
    r"([\"']?(?:tax_id|date_of_birth|card_on_file|credit_check_ref)[\"']?\s*:\s*)"
    r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^,}\]\s]+)",
    re.IGNORECASE,
)
_JSON_DECODER = json.JSONDecoder()


def strip_sensitive_fields(value):
    if isinstance(value, dict):
        return {
            key: strip_sensitive_fields(item)
            for key, item in value.items()
            if str(key).lower() not in SENSITIVE_FIELDS
        }
    if isinstance(value, list):
        return [strip_sensitive_fields(item) for item in value]
    if isinstance(value, tuple):
        return tuple(strip_sensitive_fields(item) for item in value)
    return value


def redact_trace_payload(payload):
    if isinstance(payload, dict):
        return {
            key: redact_trace_payload(value)
            for key, value in payload.items()
            if str(key).lower() not in SENSITIVE_FIELDS
        }
    if isinstance(payload, list):
        return [redact_trace_payload(value) for value in payload]
    if isinstance(payload, tuple):
        return tuple(redact_trace_payload(value) for value in payload)
    if isinstance(payload, str):
        return _redact_trace_text(payload)
    return payload


def _redact_trace_text(value):
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        parsed = None
    if isinstance(parsed, (dict, list, str)):
        redacted = redact_trace_payload(parsed)
        return json.dumps(redacted) if redacted != parsed else value

    parts = []
    cursor = 0
    search_from = 0
    while search_from < len(value):
        starts = [
            position
            for position in (
                value.find("{", search_from),
                value.find("[", search_from),
            )
            if position >= 0
        ]
        if not starts:
            break
        start = min(starts)
        try:
            parsed, end = _JSON_DECODER.raw_decode(value, start)
        except ValueError:
            search_from = start + 1
            continue
        redacted = redact_trace_payload(parsed)
        if redacted != parsed:
            parts.extend((value[cursor:start], json.dumps(redacted)))
            cursor = end
        search_from = end
    if cursor:
        parts.append(value[cursor:])
        value = "".join(parts)
    value = _SERIALIZED_BILLING_PATTERN.sub("[REDACTED]", value)
    return _SERIALIZED_FIELD_PATTERN.sub("[REDACTED]", value)
