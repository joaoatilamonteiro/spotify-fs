from imports import hashlib, random
from spotify_cliente import spotifyclient

class verificador:
    def __init__(self, client,senha):
        self.client = client
        #aqui ele criptografa a senha em hash hexadecimal
        hash_senha = hashlib.sha256(senha.encode("utf-8")).hexdigest()

        #aqui ele transforma hexadecimal em inteiro. Conhecimento novo!
        #o segundo argumento é dizendo em qual base foi escrita originalmente
        semente = int(hash_senha,16)
        #aqui ele tira a aleatoriedade da semente, dizendo que o que deve ser usado como seed
        random.seed(semente)

    def gerar_tabela(self):
        tabela_musicas = []
        #musicas que ja foram usadas vao ser guardadas nesse set
        musicas_usadas = set()
        variavel_string = "abcdefghijklmnopqrstuvwxyz"
        while len(tabela_musicas) < 256:
            letra_sorteada = random.choice(variavel_string)
            resultados = self.client.procura_musica(letra_sorteada)
            for musica in resultados:
                uri_musica = musica["uri"]
                if uri_musica not in musicas_usadas:
                    tabela_musicas.append(uri_musica)
                    musicas_usadas.add(uri_musica)
                    if len(tabela_musicas) == 256: break

        return tabela_musicas

