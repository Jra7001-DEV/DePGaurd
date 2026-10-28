.PHONY: install lint test run docker-build docker-up seed

install:
	python -m pip install -e '.[dev]'

lint:
	ruff check src tests
	black --check src tests
	mypy src

test:
	pytest --cov=depguard --cov-report=term-missing

run:
	depguard serve

docker-build:
	docker compose build

docker-up:
	docker compose up --build

seed:
	depguard db seed
