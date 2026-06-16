from fastapi import FastAPI, Request, HTTPException
import httpx
import traceback
from security import inspect_input_payload, scrub_output_text, verify_output_structural_safety

app = FastAPI(title='Cerberus Ollama Security Proxy')

# Target the local Ollama instance endpoint
OLLAMA_UPSTREAM_URL = 'http://localhost:11434/api/generate'

# Initialize connection pool for ultra-low latency lookups
async_client = httpx.AsyncClient(timeout=60.0)

@app.on_event('shutdown')
async def shutdown_event():
    await async_client.aclose()

@app.post('/api/generate')
async def security_proxy(request: Request):
    body = await request.json()
    body['model'] = 'llama3.2:1b'
    
    # Layer 1: Run Input Firewall Analysis
    if not inspect_input_payload(body):
        raise HTTPException(
            status_code=400,
            detail='Security Exception: Hostile prompt execution vector intercepted.'
        )
        
    # Strip content-length to account for explicit model setting
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ('host', 'content-length')}
    
    try:
        response = await async_client.send(
            async_client.build_request('POST', OLLAMA_UPSTREAM_URL, json=body, headers=headers)
        )
        
        if response.status_code == 200:
            response_json = response.json()
            raw_output_text = response_json.get('response', '')
            
            # Layer 2: Verify structural execution limits (Tool gating)
            if not verify_output_structural_safety(raw_output_text):
                raise HTTPException(
                    status_code=403,
                    detail='Security Exception: Destructive system action detected in model output.'
                )
                
            # Layer 3: Output Scrubbing (PII Cleanse)
            clean_output_text = scrub_output_text(raw_output_text)
            response_json['response'] = clean_output_text
            
            return response_json
        else:
            raise HTTPException(status_code=response.status_code, detail='Ollama engine error.')
    except HTTPException as he:
        raise he
        
    # Unexpected error
    except Exception as e:
        print('\n💥 --- PROXY CRASH TRACEBACK --- 💥')
        traceback.print_exc()
        print('💥 ----------------------------- 💥\n')
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=8080)