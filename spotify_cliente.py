import time
import urllib.parse
import json
import requests


#ele ler o arquivo json com as informações de login
with open("informacoes.json", "r", encoding="utf-8") as arquivo:
    dados = json.load(arquivo)

#o que vai ser requesitado
permi_spotify = ["playlist-read-private","playlist-read-collaborative","playlist-modify-private","playlist-modify-public"]

def gera_link(id_client,url_redirecionamento,permi_spotify):
    #url base que vai ser usada para depois fundir com os parametros, ja fiz coisa parecida nos trabalhos de webscrapping da ufc
    destino_base = r"https://accounts.spotify.com/authorize"

    escopo_formatado = " ".join(permi_spotify)

    parametros = {
        "client_id":id_client,
        "response_type":"code",
        "redirect_uri":url_redirecionamento,
        "scope":escopo_formatado,
        "show_dialog": "true"
    }
    #juntando a url base com os parametros
    url_formatada = f"{destino_base}?{urllib.parse.urlencode(parametros)}"

    return url_formatada

def troca_codigo_p_token(code,id_client,id_client_secret,url_redirecionamento):
    destino_base = r"https://accounts.spotify.com/api/token"

    #não entendi como funciona esse payload, sendo que nao tem o uso da urllib pra juntar os links
    #explicação do futuro: a função post ja tem um empacotador embutido, por isso que nao precisa do urlib

    #aqui é os dados que vai passar na url pra fazer a autenticação e conseguir fazer a troca
    payload = {
        "grant_type": "authorization_code",
        "code":code,
        "redirect_uri":url_redirecionamento,
        "client_id": id_client,
        "client_secret": id_client_secret
    }

    #inicia a troca, por meio de um requests.post. É algo parecido com que tem no código do cara la
    response = requests.post(destino_base, payload)

    if response.status_code == 200:
        #verifica se o token foi recebido de forma certa usando status_code
        dados_resp = response.json()
        print("Token recebido, sucesso!")
        return dados_resp["access_token"]

    else:
        print(f"erro ao carregar o token {response.text}")
        return None

class spotifyclient:
    def __init__(self,token):
        #ele passa o heards com o token
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
            #content type é apenas avisando ao spotify o que ta sendo enviado pra ele
        }

    def _faz_requisicao(self,metodo,url, **kwargs):
        while True:
            #o metodo pode ser um get, post ou put
            #url é o endereço
            #headers é o token que ja foi pegue nessa altura do campeonato
            #kwargs ele se adapta de acordo com a situação, deixa o código mais escalavel, mais generico, pronto para varias situacoes

            response = requests.request(metodo,url,headers=self.headers, **kwargs)

            if response.status_code == 429:
                tempo_fila = int(response.headers.get("Retry-After",5))
                print(f"entrando na fila, requisições maximas atingidas!\nesperando {tempo_fila} segundos")
                time.sleep(tempo_fila+1)
                continue

            return response

    def get_user_id(self):
        #não entendi como funciona essa função
        url = "https://api.spotify.com/v1/me"

        response = self._faz_requisicao("GET", url)

        if response.status_code == 200:
            dados_user = response.json()
            return dados_user["id"]
        else:
            print(f"Erro ao pegar perfil: {response.status_code}")
            return None



if __name__ == "__main__":
    # 1. Gera o link
    link = gera_link(dados["id_client"], dados["url_redirecionamento"], permi_spotify)

    print("-" * 50)
    print("1. Clique no link abaixo e faça login:")
    print(link)
    print("-" * 50)

    # 2. Pede para o usuário colar o código
    print("2. Você será redirecionado para uma página com erro (localhost).")
    print("3. Olhe a URL lá em cima e copie o código que vem depois de 'code='")
    code_recebido = input("Cole o código aqui: ").strip()  # .strip() remove espaços extras

    # Se o usuário colou a URL inteira sem querer, a gente tenta limpar
    if "code=" in code_recebido:
        code_recebido = code_recebido.split("code=")[1].split("&")[0]

    # 3. Troca pelo token
    if code_recebido:
        token = troca_codigo_p_token(code_recebido, dados["id_client"], dados["id_client_secret"], dados["url_redirecionamento"])

        if token:
            # 4. Testa a conexão
            cliente = spotifyclient(token)
            user_id = cliente.get_user_id()
            print(f"\nAutenticado com sucesso! ID do Usuário: {user_id}")
    else:
        print("Nenhum código foi inserido.")