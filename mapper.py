from imports import hashlib, random
from spotify_client import SpotifyClient 

class MusicalMapper:
    def __init__(self, client, password):
        self.client = client
        
        # Gera semente determinística baseada na senha
        password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        seed = int(password_hash, 16)
        random.seed(seed)

    def generate_mapping_table(self):
        track_table = []
        used_tracks = set() # Evita duplicatas com O(1) de busca
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        
        while len(track_table) < 256:
            # Sorteia uma letra baseada na semente da senha
            char = random.choice(alphabet)
            
            # Busca músicas usando o cliente
            results = self.client.search_track(char)
            
            for track in results:
                uri = track["uri"]
                
                if uri not in used_tracks:
                    track_table.append(uri)
                    used_tracks.add(uri)
                    
                    # Para assim que atingir 256 músicas únicas (1 byte = 1 música)
                    if len(track_table) == 256:
                        break
        
        return track_table