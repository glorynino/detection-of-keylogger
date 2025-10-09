import requests
import json
import pandas
from dotenv import load_dotenv
import os

api_key = "VOTRE_CLE_API_ICI"  # Remplace par ta clé API réelle
load_dotenv()#ici c pour maitre la cle api dans un fichier .env dans la racine du projet
API_KEY = os.getenv("API_KEY")

def query_keylogger_api(signature):
    url = "https://exemple.com/api/keyloggers"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    params = {"signature": signature}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()  # La réponse contient les infos sur le keylogger
    else:
        return None

def is_known_keylogger(api_response):
    if not api_response:
        return False
    # Exemple : la réponse contient une clé 'found' ou une liste 'results'
    return api_response.get("found", False) or len(api_response.get("results", [])) > 0

signature = "nom_du_processus_ou_hash"
result = query_keylogger_api(signature)
if is_known_keylogger(result):
    print("Keylogger connu détecté !")
    # Ici, tu peux générer une alerte ou logger l’événement 

def query_keylogger_api(signature):
    url = "https://exemple.com/api/keyloggers"
    headers = {"Authorization": f"Bearer {api_key}"}
    params = {"signature": signature}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()  # La réponse contient les infos sur le keylogger
    else:
        return None    