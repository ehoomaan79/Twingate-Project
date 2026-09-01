# Contributing

Thank you for helping improve this project.

## Development setup

1. Clone the repository.
2. Create a virtual environment:
   ```bash
   python3 -m venv .venv
   ```
3. Activate it using the shell you are currently in:
   ```bash
   source .venv/bin/activate
   ```
   or for Fish:
   ```fish
   source .venv/bin/activate.fish
   ```
4. Install the project in editable mode:
   ```bash
   python -m pip install --upgrade pip
   python -m pip install -e .[dev]
   ```
5. Run the test suite:
   ```bash
   python -m unittest discover -s tests -v
   ```

## Contribution flow

- Create a feature branch from `main`.
- Keep changes focused and easy to review.
- Add or update tests for behavior changes.
- Open a pull request with a clear summary.

## Code style

- Prefer small, readable modules.
- Keep security-related logic explicit and documented.
- Avoid unnecessary external dependencies.
