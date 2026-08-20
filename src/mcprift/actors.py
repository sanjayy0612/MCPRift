"""Identity contexts used by controlled security checks."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import StrEnum

from mcprift.client import ConnectionFailure


class ActorKind(StrEnum):
    ANONYMOUS = "anonymous"
    AUTHENTICATED = "authenticated"
    INVALID = "invalid"
    EXPIRED = "expired"


@dataclass(frozen=True)
class Actor:
    """An identity label plus an optional bearer token kept out of output."""

    name: str
    kind: ActorKind
    token: str | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("actor name cannot be empty")
        if self.kind is ActorKind.ANONYMOUS and self.token is not None:
            raise ValueError("anonymous actor cannot have a token")
        if self.kind is not ActorKind.ANONYMOUS and not self.token:
            raise ValueError("non-anonymous actor requires a token")

    @property
    def headers(self) -> dict[str, str]:
        if self.token is None:
            return {}
        return {"Authorization": f"Bearer {self.token}"}

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "kind": self.kind.value}


def actor_from_environment(name: str, kind: ActorKind, variable: str) -> Actor:
    """Load a credential without placing its value in arguments or diagnostics."""
    token = os.environ.get(variable)
    if not token:
        raise ConnectionFailure(
            "required actor credential environment variable is not set"
        )
    return Actor(name=name, kind=kind, token=token)


def standard_actors(
    *, authenticated_token: str, invalid_token: str, expired_token: str
) -> tuple[Actor, ...]:
    return (
        Actor("anonymous", ActorKind.ANONYMOUS),
        Actor("authenticated", ActorKind.AUTHENTICATED, authenticated_token),
        Actor("invalid", ActorKind.INVALID, invalid_token),
        Actor("expired", ActorKind.EXPIRED, expired_token),
    )
