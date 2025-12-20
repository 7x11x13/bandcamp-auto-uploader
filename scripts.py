import subprocess
import sys


def run_command(cmd: list[str], description: str) -> int:
    """Run a command and return its exit code."""
    print(f"\n{'=' * 60}")
    print(f"{description}")
    print(f"{'=' * 60}")
    result = subprocess.run(cmd)
    return result.returncode


def style() -> None:
    exit_codes = []

    exit_codes.append(
        run_command(
            ["ruff", "format"],
            "Formatting code with ruff",
        )
    )

    exit_codes.append(
        run_command(
            ["ruff", "check"],
            "Linting code with ruff",
        )
    )

    exit_codes.append(run_command(["mypy", "."], "Type checking with mypy"))

    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print(f"{'=' * 60}")
    print(f"Format: {'✓ PASSED' if exit_codes[0] == 0 else '✗ FAILED'}")
    print(f"Lint:   {'✓ PASSED' if exit_codes[1] == 0 else '✗ FAILED'}")
    print(f"Type:   {'✓ PASSED' if exit_codes[2] == 0 else '✗ FAILED'}")

    sys.exit(max(exit_codes))


def check() -> None:
    exit_codes = []

    exit_codes.append(
        run_command(
            ["ruff", "format", "--check"],
            "Formatting code with ruff",
        )
    )

    exit_codes.append(
        run_command(
            ["ruff", "check"],
            "Linting code with ruff",
        )
    )

    exit_codes.append(run_command(["mypy", "."], "Type checking with mypy"))

    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print(f"{'=' * 60}")
    print(f"Format: {'✓ PASSED' if exit_codes[0] == 0 else '✗ FAILED'}")
    print(f"Lint:   {'✓ PASSED' if exit_codes[1] == 0 else '✗ FAILED'}")
    print(f"Type:   {'✓ PASSED' if exit_codes[2] == 0 else '✗ FAILED'}")

    sys.exit(max(exit_codes))
