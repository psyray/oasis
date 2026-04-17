"""Structured output for LLM-based function extraction."""

from typing import List

from pydantic import BaseModel, Field


class ExtractedFunctionSpan(BaseModel):
    name: str = Field(default="anonymous")
    start: int = Field(ge=0)
    end: int = Field(ge=0)


class FunctionExtractResponse(BaseModel):
    functions: List[ExtractedFunctionSpan] = Field(default_factory=list)
