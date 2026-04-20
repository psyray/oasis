"""Shared embedding-model normalization helpers for CLI and runtime."""

from __future__ import annotations

import argparse
from typing import Iterable

from oasis.config import DEFAULT_ARGS


def parse_embed_models_csv(value: str) -> list[str]:
    """
    Parse comma-separated embedding model values into a normalized list.
    """
    if not isinstance(value, str):
        raise argparse.ArgumentTypeError("--embed-model must be a string")
    models: list[str] = []
    seen: set[str] = set()
    for raw in value.split(","):
        item = raw.strip()
        if not item:
            continue
        if item in seen:
            continue
        seen.add(item)
        models.append(item)
    if not models:
        raise argparse.ArgumentTypeError("--embed-model must contain at least one model name")
    return models


def normalize_embed_models(raw: str | Iterable[str] | None) -> list[str]:
    """
    Normalize raw embed-model values to a non-empty ordered list.
    """
    if raw is None:
        return [DEFAULT_ARGS["EMBED_MODEL"]]
    if isinstance(raw, str):
        return parse_embed_models_csv(raw)

    models: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            raise argparse.ArgumentTypeError("--embed-model entries must be strings")
        for parsed in parse_embed_models_csv(item):
            if parsed in seen:
                continue
            seen.add(parsed)
            models.append(parsed)
    if not models:
        raise argparse.ArgumentTypeError("--embed-model must contain at least one model name")
    return models


def primary_embed_model(raw: str | Iterable[str] | None) -> str:
    """
    Return the first embedding model from normalized values.
    """
    return normalize_embed_models(raw)[0]


def resolve_embed_models(raw: str | Iterable[str] | None) -> tuple[list[str], str]:
    """
    Resolve both normalized embed models and primary model in one call.
    """
    models = normalize_embed_models(raw)
    return models, models[0]
