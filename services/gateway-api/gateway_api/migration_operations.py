from __future__ import annotations

import re
from dataclasses import dataclass

IDENTIFIER_PATTERN = re.compile(r"^[a-z_][a-z0-9_]*$")
PREDICATE_PATTERN = re.compile(r"^[A-Za-z0-9_,'()=\s]+$")


@dataclass(frozen=True, slots=True)
class CreateIndexConcurrently:
    name: str
    table: str
    columns: tuple[str, ...]
    predicate: str

    def __post_init__(self) -> None:
        for field_name, value in (("name", self.name), ("table", self.table)):
            if not IDENTIFIER_PATTERN.fullmatch(value):
                raise ValueError(
                    f"invalid {field_name} for concurrent index: {value!r}"
                )
        if not isinstance(self.columns, tuple) or not self.columns:
            raise TypeError("concurrent index columns must be a non-empty tuple")
        for column in self.columns:
            if not isinstance(column, str) or not IDENTIFIER_PATTERN.fullmatch(column):
                raise ValueError(f"invalid concurrent index column: {column!r}")
        predicate = self.predicate.strip()
        if (
            not predicate
            or len(predicate) > 1000
            or not PREDICATE_PATTERN.fullmatch(predicate)
        ):
            raise ValueError(
                "concurrent index predicate is not a bounded safe expression"
            )


def create_index_concurrently(
    *,
    name: str,
    table: str,
    columns: tuple[str, ...],
    predicate: str,
) -> CreateIndexConcurrently:
    return CreateIndexConcurrently(
        name=name,
        table=table,
        columns=columns,
        predicate=predicate,
    )
