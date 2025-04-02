# Install dependencies
install:
	python -m pip install --upgrade pip
	pip install -r requirements.txt
	pip install ruff black

# Run linter (ruff)
lint:
	ruff check .

# Clean up Python cache files
clean:
	find . -type d -name "__pycache__" -exec rm -r {} +
	find . -type f -name "*.pyc" -delete

# Format code
format:
	black .

# Check for outdated packages
outdated:
	pip list --outdated

# Create virtual environment
venv:
	python3.11 -m venv venv
	. venv/bin/activate && pip install --upgrade pip
	. venv/bin/activate && make install
