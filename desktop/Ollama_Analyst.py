import json
import urllib.request

# --- 1. CONFIGURATION ---
# We point to the container name "soc-ollama" because we are on the same "soc-net" network
OLLAMA_URL = "http://soc-ollama:11434/api/generate"
MODEL = "cogito:3b"  # Make sure you ran 'ollama pull llama3'

# --- 2. DATA INJECTION ---
# Grab the CLEAN output from the previous node
INPUT_JSON = r'''{{ $feature_extractor }}'''

# --- 3. CONSTRUCT PROMPT ---
# We ask the LLM to act as a Level 2 Analyst
prompt = f"""
You are a Senior SOC Analyst. Review the following extracted email features and provide a verdict.
Focus on:
- High URL entropy (indicates random/generated domains)
- IP addresses in URLs
- Mismatches between 'From' and 'Reply-To'
- Phishing keywords

DATA JSON:
{INPUT_JSON}

TASK:
Provide a JSON response with exactly these keys:
- "reasoning": A short 1-sentence explanation of why it is safe or malicious.
- "confidence": A score between 0-100.
- "verdict": "SAFE", "SUSPICIOUS", or "MALICIOUS".
"""

# --- 4. SEND TO OLLAMA ---
payload = {
    "model": MODEL,
    "prompt": prompt,
    "stream": False,
    "format": "json"  # Forces Ollama to reply in strict JSON
}

try:
    # We use urllib to avoid dependency issues with 'requests' in minimal containers
    req = urllib.request.Request(
        OLLAMA_URL, 
        data=json.dumps(payload).encode('utf-8'), 
        headers={'Content-Type': 'application/json'}
    )
    
    with urllib.request.urlopen(req) as response:
        result = json.loads(response.read().decode('utf-8'))
        
        # The LLM's text reply is inside the "response" key
        llm_text = result.get("response", "{}")
        
        # Parse the inner JSON from the LLM
        try:
            analysis = json.loads(llm_text)
        except:
            # Fallback if LLM didn't give perfect JSON
            analysis = {"raw_output": llm_text, "verdict": "UNKNOWN"}

    # --- 5. OUTPUT ---
    print(json.dumps({
        "success": True,
        "model_used": MODEL,
        "ai_analysis": analysis
    }))

except Exception as e:
    print(json.dumps({"success": False, "error": f"Ollama Connection Failed: {str(e)}"}))