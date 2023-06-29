

Run OpenID Whisperer (from project root)
```
poetry run python -m mock_api_service.mock_api_service > nul 2>&1
```

Run Mock-API (from project root)
```
poetry run python -m mock_api_service.mock_api_service > nul 2>&1
```

Run pytests with coverage
```
poetry run coverage run -m pytest && poetry run coverage report -m
```
