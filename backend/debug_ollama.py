import urllib.request
import json
import sys

def check_ollama():
    url = "http://localhost:11434/api/tags"
    try:
        print(f"Checking models at {url}...", flush=True)
        with urllib.request.urlopen(url) as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                models = data.get('models', [])
                print("Available models:", flush=True)
                for m in models:
                    print(f" - {m['name']}", flush=True)
            else:
                print(f"Error listing models: {response.status}", flush=True)
            
        # Test generation with config default
        test_model = "qwen2.5:1.5b"
        print(f"\nTesting generation with model: {test_model}...", flush=True)
        
        gen_url = "http://localhost:11434/api/generate"
        payload = {
            "model": test_model,
            "prompt": "Hello",
            "stream": False
        }
        
        req = urllib.request.Request(gen_url, 
                                     data=json.dumps(payload).encode('utf-8'),
                                     headers={'Content-Type': 'application/json'})
        
        with urllib.request.urlopen(req) as res:
            if res.status == 200:
                print("Success! Response from Ollama:", flush=True)
                data = json.loads(res.read().decode())
                print(data.get('response'), flush=True)
            else:
                print(f"Failed to generate: {res.status}", flush=True)

    except Exception as e:
        print(f"Connection failed: {e}", flush=True)

if __name__ == "__main__":
    check_ollama()
