import os
import requests
import json

def call_gemini_api(prompt: str) -> dict:
    """
    Função isolada para fazer a chamada para a API do Gemini.
    Usa a chave de API carregada no ambiente principal.
    Retorna um dicionário com os dados ou com um erro.
    """
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

    if not GEMINI_API_KEY:
        return {"error": {"message": "Chave de API do Gemini não foi encontrada no ambiente do servidor."}, "status_code": 500}

    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    
    headers = {'Content-Type': 'application/json'}
    
    payload = {
        "contents": [{"parts": [{"text": prompt}]}]
    }

    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=60)
        
        # Retorna os dados e o status, seja sucesso ou erro
        if response.ok:
            return {"data": response.json(), "status_code": response.status_code}
        else:
            return {"error": response.json().get("error", {"message": "Erro desconhecido da API"}), "status_code": response.status_code}

    except requests.exceptions.RequestException as e:
        return {"error": {"message": f"Erro de comunicação de rede: {e}"}, "status_code": 503}
