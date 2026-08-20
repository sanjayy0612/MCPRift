"""A deliberately small registry for stable built-in security cases."""

from __future__ import annotations

from mcprift.security import SecurityCase, built_in_cases


class CaseRegistry:
    def __init__(self) -> None:
        self._cases: dict[str, SecurityCase] = {}

    def register(self, case: SecurityCase) -> None:
        if case.case_id in self._cases:
            raise ValueError(f"duplicate security case: {case.case_id}")
        self._cases[case.case_id] = case

    def get(self, case_id: str) -> SecurityCase:
        try:
            return self._cases[case_id]
        except KeyError as error:
            raise ValueError("unknown security case") from error

    def all(self) -> tuple[SecurityCase, ...]:
        return tuple(self._cases.values())


def default_registry(
    *, alice_token: str, bob_token: str, invalid_token: str, expired_token: str
) -> CaseRegistry:
    registry = CaseRegistry()
    for case in built_in_cases(
        alice_token=alice_token,
        bob_token=bob_token,
        invalid_token=invalid_token,
        expired_token=expired_token,
    ):
        registry.register(case)
    return registry
