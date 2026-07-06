import requests  # Import the requests library to send HTTP requests from Python.

url = "http://127.0.0.1:11434/api/generate"  # Define the Ollama REST API endpoint for text generation.

question = input("Ask Anything: ")  # Read the user's question from the console input.

answer = requests.post(  # Send an HTTP POST request to the Ollama API.
    url,  # Target API URL where the request is sent.
    json={  # Request payload in JSON format.
        "model": "qwen3:1.7b",  # Specify which local LLM model to use for response generation.
        "prompt": question,  # Pass the user's question as the model prompt.
        "stream": False  # Request a single complete response instead of token-by-token streaming.
    },
    timeout=60  # Set a maximum wait time of 60 seconds for the API response.
)

print(answer.json().get("response", "No Response"))  # Parse JSON output and print model response; show default text if key is missing.