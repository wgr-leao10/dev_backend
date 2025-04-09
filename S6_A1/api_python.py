import requests

def obter_previsao(cidade):
    url = f"http://api.weatherapi.com/v1/current.json?key=SUA_CHAVE_API&q={cidade}"
