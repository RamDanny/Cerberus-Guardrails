# Cerberus-Guardrails
Simple guardrails system to protect prompt injection in Ollama

* Run `server.py` and `client.py` in separate terminals.
* `client.py` tries a set of test cases (both malicious and benign)
* `server.py` handles the request, before validating the prompt with regex checking for bad patterns.
* `security.py` is the module containing the checks for the malicious regex patterns used in `server.py`
