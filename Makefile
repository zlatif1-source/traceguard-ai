.PHONY: install run test lint eval docker

install:
	python -m pip install -r requirements-dev.txt

run:
	uvicorn app.main:app --reload

test:
	pytest --cov=app --cov-report=term-missing

lint:
	ruff check .

eval:
	python -m evals.run_evals

docker:
	docker compose up --build

