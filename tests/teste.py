import json

with open('resultados_03.json', 'r', encoding='utf-8') as f:
    dados = json.load(f)
    
print("Chaves principais:", list(dados.keys()))
if 'resultados' in dados:
    print("Número de domínios:", len(dados['resultados']))
else:
    print("Estrutura diferente do esperado!")
    print("Primeiras chaves encontradas:", list(dados.keys()))
    # Para entender melhor a estrutura real
    if isinstance(dados, dict):
        primeira_chave = next(iter(dados), None)
        if primeira_chave:
            print(f"Exemplo do conteúdo da chave '{primeira_chave}':", dados[primeira_chave])