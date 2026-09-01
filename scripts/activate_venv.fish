set SCRIPT_DIR (cd (dirname (status --current-filename)) && pwd)
set VENV_DIR "$SCRIPT_DIR/../.venv"

if test -f "$VENV_DIR/bin/activate.fish"
    source "$VENV_DIR/bin/activate.fish"
else
    echo "Virtual environment not found at $VENV_DIR" >&2
end
