from mapper import MusicalMapper
from imports import *

# Carrega configurações
with open("informacoes.json", "r", encoding="utf-8") as file:
    config = json.load(file)

SCOPES = ["playlist-read-private", "playlist-read-collaborative", "playlist-modify-private", "playlist-modify-public"]

def get_auth_url(client_id, redirect_uri, scopes):
    base_url = "https://accounts.spotify.com/authorize"
    scope_str = " ".join(scopes)

    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope_str,
        "show_dialog": "true"
    }
    
    return f"{base_url}?{urllib.parse.urlencode(params)}"

def exchange_code_for_token(code, client_id, client_secret, redirect_uri):
    url = "https://accounts.spotify.com/api/token"
    
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret
    }

    response = requests.post(url, data=payload)

    if response.status_code == 200:
        print("Token received successfully!")
        return response.json()["access_token"]
    else:
        print(f"Error loading token: {response.text}")
        return None

class SpotifyClient:
    def __init__(self, token):
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    def _make_request(self, method, url, **kwargs):
        while True:
            response = requests.request(method, url, headers=self.headers, **kwargs)

            # Tratamento de Rate Limit (Erro 429)
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 5))
                print(f"Rate limit reached. Waiting {retry_after} seconds...")
                time.sleep(retry_after + 1)
                continue

            return response

    def get_user_id(self):
        url = "https://api.spotify.com/v1/me"
        response = self._make_request("GET", url)

        if response.status_code == 200:
            return response.json()["id"]
        else:
            print(f"Error fetching profile: {response.status_code}")
            return None

    def search_track(self, query):
        url = "https://api.spotify.com/v1/search"
        params = {
            "q": query,
            "type": "track",
            "limit": 50
        }
        
        response = self._make_request("GET", url, params=params)

        if response.status_code == 200:
            return response.json()["tracks"]["items"]
        else:
            print(f"Search error: {response.status_code}")
            return []

    def create_playlist(self,id_user,name_playlist,description):
        url_create_playlist = f"https://api.spotify.com/v1/users/{id_user}/playlists"

        payload = {
            "name": name_playlist,
            "description": description,
            "public": False
        }

        response = self._make_request("POST",url_create_playlist, json = payload)

        if response.status_code == 201:
            return response.json()["id"]
        else:
            print(f"Search error: {response.status_code}")
            return None


    def add_track_playlist(self,id_playlist,track_list):
        #TODO Montamos o endereço de entrega usando o ID que recebemos
        url = f"https://api.spotify.com/v1/playlists/{id_playlist}/tracks"

        #TODO Descobrimos o tamanho total do arquivo (quantas músicas tem na lista)
        size_track_list = len(track_list)
        #TODO Criamos o loop que pula de 100 em 100
        for i in range (0, size_track_list, 100):
        #TODO Fatiamos a lista! (Pega do item atual 'i' até o 'i + 100')
            pacote = track_list[i: i+100]
        #TODO Colocamos as 100 músicas no envelope exigido pelo Spotify
            payload = {"uris": pacote}
        #TODO Fazemos a entrega (POST)
            response = self._make_request("POST", url, json=payload)
            if response.status_code != 201:
                print(f"Search error: {response.status_code}")



# Variável global para o servidor local
captured_code = None

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return # Silencia logs

    def do_GET(self):
        global captured_code
        if "/callback/spotify" in self.path:
            query = urllib.parse.urlparse(self.path).query
            query_components = urllib.parse.parse_qs(query)

            if "code" in query_components:
                captured_code = query_components["code"][0]
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>Success! You can close this tab.</h1>")
                self.wfile.write(b"<script>window.close();</script>")
            else:
                self.send_error(400, "Code not found")

def auto_login(client_id, client_secret, redirect_uri, scopes):
    link = get_auth_url(client_id, redirect_uri, scopes)
    
    print("Opening browser for login...")
    webbrowser.open(link)

    # Inicia servidor local para esperar a resposta
    server_address = ('127.0.0.1', 8080)
    httpd = HTTPServer(server_address, RequestHandler)

    print("Waiting for Spotify callback...")
    httpd.handle_request() # Espera uma única requisição e encerra

    if captured_code:
        return exchange_code_for_token(captured_code, client_id, client_secret, redirect_uri)
    else:
        print("Failed to capture code.")
        return None
