from typing import Protocol, ClassVar, runtime_checkable, Any
from avaguard_core.checks.base_check import CheckResult

@runtime_checkable
class CheckProtocol(Protocol):
    """
    Structural type contract for a CIS Compliance Check.

    Any class satisfying this Protocol can be used as a check in the engine,
    regardless of inheritance. Use @runtime_checkable to allow isinstance() checks.

    Usage:
        def run_check(check: Type[CheckProtocol]) -> CheckResult:
            instance = check(graph_client, config)
            return instance.execute()
    """

    CHECK_ID: ClassVar[str]
    TITLE: ClassVar[str]
    DESCRIPTION: ClassVar[str]
    CIS_CONTROL_ID: ClassVar[str]
    CIS_SEVERITY: ClassVar[Any]

    def execute(self) -> CheckResult:
        """Execute the compliance check and return a standardized CheckResult."""
        ...
