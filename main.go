package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/spotify"
)

type AuthHandler struct {
	Config   *oauth2.Config
	Verifier string
	Token    *oauth2.Token
	Done     chan struct{}
}

func (H *AuthHandler) generateSpotifyAuthLink() {

	H.Verifier = oauth2.GenerateVerifier()
	url := H.Config.AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(H.Verifier))
	fmt.Printf("Visit the URL for the auth dialog: %v", url)

}

func (H *AuthHandler) exchangeToToken(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		fmt.Println("Code not found")
		return
	}
	token, err := H.Config.Exchange(context.Background(), code, oauth2.VerifierOption(H.Verifier))
	if err != nil {
		log.Printf("Failed to exchange token.: %s\n", err.Error())
		return
	}
	H.Token = token
	fmt.Fprintf(w, "Authenticated successfully! Access Token: %s", token.AccessToken)
	fmt.Println("Access Token:", token.AccessToken)
	H.Done <- struct{}{}
	close(H.Done)
}

func (H *AuthHandler) getPlaylistData(id string) {
	req, err := http.NewRequest(http.MethodGet, "https://api.spotify.com/v1/playlists/"+id, nil)
	if err != nil {
		log.Fatalf("Error creating the request: %s", err)
	}

	req.Header.Set("Authorization", "Bearer "+H.Token.AccessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error executing the request: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading the response body: %s", err)
	}

	fmt.Println(string(body))

}

func main() {
	clientID, exist := os.LookupEnv("SPOTIFY_CLIENTID")
	if !exist {
		log.Fatalln("SPOTIFY_CLIENTID system env var not found")
	}

	clientSecret, exist := os.LookupEnv("SPOTIFY_CLIENTSECRET")
	if !exist {
		log.Fatalln("SPOTIFY_CLIENTSECRET system env var not found")
	}

	conf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"playlist-read-private", "playlist-read-collaborative", "playlist-modify-private", "playlist-modify-public"},
		Endpoint:     spotify.Endpoint,
		RedirectURL:  "http://127.0.0.1:8080/callback/spotify",
	}

	authStruct := AuthHandler{
		Config: conf,
		Done:   make(chan struct{}),
	}
	go authStruct.generateSpotifyAuthLink()

	mux := http.NewServeMux()
	mux.HandleFunc("/callback/spotify", authStruct.exchangeToToken)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	go func() {
		fmt.Println("Servidor rodando na porta 8080...")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(fmt.Sprintf("Error starting server: %s", err))
		}
	}()

	select {
	case <-authStruct.Done:
		fmt.Println("Token received! Stoping http server.")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			fmt.Printf("Error to shutdown the web server: %v\n", err)
		}

		fmt.Println("Server is shutdown")
		break

	case <-time.After(60 * time.Second):
		fmt.Println("Timeout, shutdowning server.")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			fmt.Printf("Error to shutdown the web server: %v\n", err)
		}

		fmt.Println("Server is shutdown")
		return
	}

	authStruct.getPlaylistData("4g0lUdrr5JfmidRZaHf0x5")

}
