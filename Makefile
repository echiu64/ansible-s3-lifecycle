# for testing
test: 
	PYTHONPATH=src python -m unittest discover -s tests -p '*.py' -v
