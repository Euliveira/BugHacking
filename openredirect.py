import requests
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

print("""                 DESENVOLVEDOR: WILLIAN DE OLIVEIRA""")

# Lista ampliada de parâmetros que podem indicar redirecionamento
redirect_params = [
    "url", "redirect", "return", "next", "goto", "continue", "target", "destination",
    "redir", "forward", "to", "ref", "reference", "site", "path", "callback", "view", "link",
    "r", "u", "link", "out", "view", "return_url", "returnTo", "rurl", "return_to",
    "return-path", "returnToURL", "return_url", "next_url", "redirect_uri", "redirect_url",
    "redirect_to", "redirect_path", "continue_to", "target_url", "target_uri", "target_path",
    "goto_url", "goto_uri", "goto_path", "continue_url", "continue_uri", "continue_path",
    "destination_url", "destination_uri", "destination_path", "redir_url", "redir_uri", "redir_path",
    "forward_url", "forward_uri", "forward_path", "to_url", "to_uri", "to_path",
    "ref_url", "ref_uri", "ref_path", "reference_url", "reference_uri", "reference_path",
    "site_url", "site_uri", "site_path", "callback_url", "callback_uri", "callback_path",
    "url_link", "out_link"
]

# URL maliciosa para redirecionar
malicious_url = "http://malicious.com"

def is_redirect(response):
    """
    Verifica se a resposta HTTP é um redirecionamento para o URL malicioso.
    """
    return response.status_code in (301, 302, 303, 307, 308) and malicious_url in response.headers.get('Location', '')

def test_open_redirect(base_url, params, malicious_url):
    """
    Testa a URL alvo para vulnerabilidades de Open Redirect.
    """
    parsed_url = urlparse(base_url)
    original_params = parse_qs(parsed_url.query)

    for param in params:
        # Atualiza os parâmetros com a URL maliciosa
        test_params = original_params.copy()
        test_params[param] = malicious_url

        # Reconstrói a URL com os novos parâmetros
        test_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed_url._replace(query=test_query))

        print(f"Testando URL: {test_url}")

        # Realiza a requisição HTTP
        try:
            response = requests.get(test_url, allow_redirects=False)
            if is_redirect(response):
                print(f"Possível vulnerabilidade de Open Redirect detectada em parâmetro: {param}")
            else:
                print(f"Parâmetro {param} parece seguro.")
        except requests.RequestException as e:
            print(f"Erro ao testar {test_url}: {e}")

# Solicita a URL base do usuário
base_url = input("Digite a URL base para testar (exemplo: https://example.com): ")

# URLs específicas para testar com parâmetros comuns
specific_paths = [
    "",               # Página inicial
    "/login",         # Página de login
    "/logout",        # Página de logout
    "/register",      # Página de registro
    "/signup",        # Página de inscrição
    "/checkout",      # Página de checkout
    "/subscribe",     # Página de subscrição
    "/error"          # Página de erro
]

# Executa os testes para cada caminho específico
for path in specific_paths:
    full_url = base_url.rstrip('/') + path
    test_open_redirect(full_url, redirect_params, malicious_url)