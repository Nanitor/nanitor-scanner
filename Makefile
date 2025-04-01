# Install dependencies
install:
	python -m pip install --upgrade pip
	pip install -r requirements.txt
	pip install ruff

# Run linter
lint:
	ruff check .

# Clean up Python cache files
clean:
	find . -type d -name "__pycache__" -exec rm -r {} +
	find . -type f -name "*.pyc" -delete

# Update dependencies
update-deps:
	pip install --upgrade -r requirements.txt
	pip freeze > requirements.txt

# Format code
format:
	black .

# Check for outdated packages
outdated:
	pip list --outdated

# Create virtual environment
venv:
	python -m venv venv
	. venv/bin/activate && pip install --upgrade pip
	. venv/bin/activate && make install
