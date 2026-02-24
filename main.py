import os
import time
from spotify_client import SpotifyClient, auto_login, SCOPES
from mapper import MusicalMapper
import json

def main():
    #ato 1
    with open("informacoes.json", "r", encoding="utf-8") as arquivo:
        dados = json.load(arquivo)

    token = auto_login(
              dados["id_client"],
              dados["id_client_secret"],
              dados["url_redirecionamento"],
              SCOPES
    )

    if not token:
        print("Falha ao obter o token de acesso")
        return

    client = SpotifyClient(token)
    print(f"Login feito com sucesso\nBem vindo: {client.get_user_id()}")

    seed = input("Digite a palavra-senha que gerará a criptografia").strip()
    mapper = MusicalMapper(client, seed)

    print("Gerando dicionário de tradução para criptografia...")
    tabela_traducao = mapper.generate_mapping_table()

    #ato 2

    track_gigant_list = []
    caminho = input("Digite o caminho do arquivo que deseja criptografar").strip()

    with open(caminho, "rb") as arquivo:
        dados = arquivo.read()
        nome_arquivo = os.path.basename(caminho)
        print(f"Lendo e traduzindo o arquivo {nome_arquivo}\ntamanho em bytes:{len(dados)} ")

        for byte in dados:
            uri_music = tabela_traducao[byte]
            track_gigant_list.append(uri_music)

    print(f"Tradução concluída! O arquivo virou uma lista de {len(track_gigant_list)} musicas")

    #ato 3

    max_size_playlist = 10000
    total_music = len(track_gigant_list)
    if total_music == 0:
        print("Arquivo vazio. Não há nada para enviar")

    volume = 1

    for i in range(0,total_music,max_size_playlist):
        pedaco_10k = track_gigant_list[i:i+max_size_playlist]

        nome_playlist = f"Arquivo:{nome_arquivo} - Vol {volume}"
        descricao = f"Volume {volume} do arquivo {nome_arquivo}"

        print(f"Criando playlist: {nome_playlist}")

        lock_secury = False

        while not lock_secury:

            new_id_playlist = client.create_playlist(client.get_user_id(),nome_playlist,descricao)

            if new_id_playlist:
                print(f"Adicionando {len(pedaco_10k)} musicas na playlist...")

                client.add_track_playlist(new_id_playlist, pedaco_10k)
                print(f"Volume {volume} finalizado com sucesso")
                lock_secury = True
                volume += 1

            else:
                print(f"erro ao tentar criar o volume {volume}")
                time.sleep(5)
    print("UPLOAD CONCLUÍDO! O seu arquivo está seguro e escondido no Spotify.")

    # Essa linha garante que o Maestro só toque a música se você rodar este arquivo direto
if __name__ == "__main__":
    main()






























