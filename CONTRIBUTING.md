# Contributing

Thank you for helping improve this project.

## Development setup

1. Clone the repository.
2. Create the project virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. Install the common dependencies:
   ```bash
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```
4. Run the project tests:
   ```bash
   python -m unittest discover -s tests -v
   ```
5. For a specific module, use its own directory and requirements file:
   ```bash
   cd modules/relay
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

## Contribution flow

- Create a feature branch from `main`.
- Keep each change focused on one module or one concern.
- Add or update tests for behavior changes.
- Keep module-specific install instructions current.
- Open a pull request with a summary of the architecture impact.

## Project conventions

- Each deployable component lives under `modules/`.
- Shared logic lives under `zero_trust_core/`.
- Use real behavior tests instead of mock-only validation.
- Keep security design decisions explicit and documented.
- Avoid adding broad dependencies without a clear reason.
