# Vulnerable AI Demo Application

This directory contains a deliberately vulnerable AI application designed for testing **LLM-RTK**.

The application simulates common security weaknesses that may appear in GenAI systems, allowing researchers to observe how LLM-RTK detects vulnerabilities.

## Simulated Vulnerabilities

The application intentionally includes behaviors such as:

* system prompt disclosure
* secret exposure
* policy override responses
* role escalation prompts

These behaviors mimic common weaknesses described in the **OWASP Top 10 for LLM Applications**.

## Running the Demo

Start the demo application:

```
python app.py
```

The AI endpoint will be available at:

```
http://localhost:5000/chat
```

You can then run LLM-RTK against this endpoint.

Example:

```
llm-rtk --url http://localhost:5000/chat --objectives all
```
