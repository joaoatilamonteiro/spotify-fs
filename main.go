package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mathRand "math/rand/v2"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/spotify"
)

const (
	ServerPort                 = ":8080"
	Charset                    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	LengthRNGString            = 5
	SpotifyMaxTracksPerRequest = 100
	numWorkers                 = 4
	saltSize                   = 16
	keySize                    = 32
	pbkdfIterations            = 100000
	RateLimitWaitTime          = 5
	maxBytesPerPlaylist        = 10000
)

type WriteJob struct {
	PlaylistID string
	Chunks     [][]byte
}

type ReadJob struct {
	Sequence   int
	PlaylistID string
}

type ReadResult struct {
	Sequence int
	Data     []byte
	NextID   string
}

type AuthSpotify struct {
	Config   *oauth2.Config
	Verifier string
	Token    *oauth2.Token
	Done     chan struct{}
}

type SpotifyClient struct {
	Auth      *AuthSpotify
	ClientID  string
	WebConfig WebClient
}

type SpotifyHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type WebClient struct {
	client                SpotifyHTTPClient
	SpotifySearchURL      string
	SpotifyUserURL        string
	CreatePlaylistURL     string
	PlaylistURL           string
	ChangePlaylistDetails string
	GetPlaylist           string
}

type SpotifySearchResponse struct {
	Tracks TracksWrapper `json:"tracks"`
}

type TracksWrapper struct {
	Items []SpotifyItem `json:"items"`
}

type SpotifyItem struct {
	URI string `json:"uri"`
}

type PlaylistInfo struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Public      *bool  `json:"public,omitempty"`
}

type PlaylistItems struct {
	Next  string `json:"next"`
	Items []struct {
		Track struct {
			Uri string `json:"uri"`
		} `json:"track"`
	} `json:"items"`
}

type ErrorDetail struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

type SpotifyPlaylistID struct {
	ID string `json:"id"`
}

type SpotifyUserID struct {
	ID string `json:"id"`
}

type SpotifyAddPlaylist struct {
	MusicURIS []string `json:"uris"`
}

func (a *AuthSpotify) generateSpotifyAuthLink() {

	a.Verifier = oauth2.GenerateVerifier()
	url := a.Config.AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(a.Verifier))
	fmt.Printf("Visit the URL for the auth dialog: %v\n", url)

}

func saveMap(path string, m map[string]byte, password string) error {
	var gobBuffer bytes.Buffer
	if err := gob.NewEncoder(&gobBuffer).Encode(m); err != nil {
		return err
	}
	plaintext := gobBuffer.Bytes()

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	key := pbkdf2.Key([]byte(password), salt, pbkdfIterations, keySize, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	file.Write(salt)
	file.Write(nonce)
	file.Write(ciphertext)

	return nil

}

func loadMap(path, password string) (map[string]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(make([]byte, keySize))
	if err != nil {
		return nil, err
	}
	gcmTemp, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcmTemp.NonceSize()

	if len(data) < saltSize+nonceSize {
		return nil, errors.New("corrupted or too short file")
	}

	salt := data[:saltSize]
	nonce := data[saltSize : saltSize+nonceSize]
	ciphertext := data[saltSize+nonceSize:]

	key := pbkdf2.Key([]byte(password), salt, pbkdfIterations, keySize, sha256.New)

	block, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("Decryption failed: incorrect password or altered data.")
	}

	var result map[string]byte
	reader := bytes.NewReader(plaintext)
	err = gob.NewDecoder(reader).Decode(&result)

	return result, err
}

func (a *AuthSpotify) exchangeToToken(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		fmt.Println("Code not found")
		return
	}
	token, err := a.Config.Exchange(context.Background(), code, oauth2.VerifierOption(a.Verifier))
	if err != nil {
		log.Printf("Failed to exchange token.: %s\n", err.Error())
		return
	}
	a.Token = token
	fmt.Fprintf(w, "Authenticated successfully! Access Token: %s", token.AccessToken)
	fmt.Println("Access Token:", token.AccessToken)
	close(a.Done)
}

func (s *SpotifyClient) GetUserID(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.WebConfig.SpotifyUserURL, nil)
	if err != nil {
		return fmt.Errorf("Error creating the request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.Auth.Token.AccessToken)

	resp, err := s.WebConfig.client.Do(req)

	if err != nil {
		return fmt.Errorf("Error executing the request: %w", err)
	}
	defer resp.Body.Close()

	var response SpotifyUserID
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return fmt.Errorf("Error reading JSON: %w", err)
	}

	s.ClientID = response.ID
	return nil
}

func NewAuthHandler() (*AuthSpotify, error) {
	clientID, exist := os.LookupEnv("SPOTIFY_CLIENTID")
	if !exist {
		return nil, errors.New("SPOTIFY_CLIENTID system env var not found")
	}

	clientSecret, exist := os.LookupEnv("SPOTIFY_CLIENTSECRET")
	if !exist {
		return nil, errors.New("SPOTIFY_CLIENTSECRET system env var not found")
	}

	conf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"playlist-read-private", "playlist-read-collaborative", "playlist-modify-private", "playlist-modify-public"},
		Endpoint:     spotify.Endpoint,
		RedirectURL:  fmt.Sprintf("http://127.0.0.1%s/callback/spotify", ServerPort),
	}

	authStruct := &AuthSpotify{
		Config: conf,
		Done:   make(chan struct{}),
	}

	return authStruct, nil

}

func NewHttpServer(authStruct *AuthSpotify) (srv *http.Server) {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback/spotify", authStruct.exchangeToToken)

	srv = &http.Server{
		Addr:    ServerPort,
		Handler: mux,
	}

	return srv

}

func NewRNGStringWithSeed(length int, hash []byte, modifier uint64) string {
	baseSeed := binary.BigEndian.Uint64(hash)

	seed := baseSeed + modifier

	source := mathRand.NewPCG(seed, 0)
	r := mathRand.New(source)

	var sb strings.Builder
	sb.Grow(length)

	for i := 0; i < length; i++ {
		randomIndex := r.IntN(len(Charset))
		sb.WriteByte(Charset[randomIndex])
	}
	return sb.String()
}

func (s *SpotifyClient) NewDictionary(ctx context.Context, password string) (map[byte]string, map[string]byte, error) {
	h := sha256.New()
	h.Write([]byte(password))
	hash := h.Sum(nil)

	foundCount := 0
	byteCount := byte(0)
	seedDiff := uint64(0)
	writerDictionary := make(map[byte]string, 256)
	readerDictionary := make(map[string]byte, 256)

	if len(hash) < 8 {
		return nil, nil, fmt.Errorf("Hash has less than 8 bytes")
	}

	for foundCount <= 255 {
		err := func() error {
			searchString := NewRNGStringWithSeed(LengthRNGString, hash[:8], seedDiff)

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.WebConfig.SpotifySearchURL, nil)
			if err != nil {
				log.Printf("Error creating the request: %s\n Trying Again...", err)
				return nil
			}

			req.Header.Set("Authorization", "Bearer "+s.Auth.Token.AccessToken)

			query := req.URL.Query()
			query.Add("q", searchString)
			query.Add("type", "track")
			query.Add("limit", "1")
			query.Add("market", "US")

			req.URL.RawQuery = query.Encode()

			resp, err := s.WebConfig.client.Do(req)
			if err != nil {
				if ctx.Err() != nil {
					return fmt.Errorf("Error with context: %s", ctx.Err().Error())
				}
				log.Printf("Error executing the request: %s\n Trying Again...", err)
				return nil
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				log.Printf("Unexpected status: %d\n Trying Again...", resp.StatusCode)
				return nil
			}

			var response SpotifySearchResponse
			err = json.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				log.Printf("Error reading JSON: %v\n Trying Again...", err)
				return nil
			}

			if len(response.Tracks.Items) > 0 {

				if _, alreadyExists := readerDictionary[response.Tracks.Items[0].URI]; alreadyExists {
					log.Printf("Collision detected for track %s. Trying another one...", response.Tracks.Items[0].URI)
					return nil
				}

				writerDictionary[byteCount] = response.Tracks.Items[0].URI
				readerDictionary[response.Tracks.Items[0].URI] = byteCount
				byteCount++
				foundCount++
			}

			return nil
		}()
		log.Printf("Track %d/256\n", foundCount)

		seedDiff++

		if err != nil {
			return nil, nil, err
		}
	}

	return writerDictionary, readerDictionary, nil
}

func (s *SpotifyClient) EditPlaylistDescription(ctx context.Context, newPlaylistID, oldPlaylistID string) error {
	RateLimitMultiplier := 1
	playlistInfo := PlaylistInfo{
		Description: newPlaylistID,
	}
	jsonData, err := json.Marshal(playlistInfo)
	if err != nil {
		return fmt.Errorf("Error marshaling struct: %w", err)
	}

	for {
		requestBody := bytes.NewBuffer(jsonData)

		req, err := http.NewRequestWithContext(ctx, http.MethodPut, fmt.Sprintf(s.WebConfig.ChangePlaylistDetails, oldPlaylistID), requestBody)
		if err != nil {
			return fmt.Errorf("Error creating the request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+s.Auth.Token.AccessToken)

		req.Header.Set("Content-Type", "application/json")

		resp, err := s.WebConfig.client.Do(req)
		if err != nil {
			return fmt.Errorf("Error while doing request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode > 299 || resp.StatusCode < 200 {
			if resp.StatusCode == 429 {
				rateLimitTime := RateLimitWaitTime * RateLimitMultiplier
				log.Printf("Error while adding to playlist (Rate limit). Trying again in %d seconds...", rateLimitTime)
				time.Sleep(time.Duration(rateLimitTime) * time.Second)
				RateLimitMultiplier++
				continue
			}

			if resp.StatusCode == 502 {
				log.Printf("Error while adding to playlist. Trying again in %d seconds...", 1)
				time.Sleep(1 * time.Second)
				RateLimitMultiplier++
				continue
			}

			var errResp ErrorResponse

			err := json.NewDecoder(resp.Body).Decode(&errResp)
			if err != nil {
				return fmt.Errorf("Error decoding JSON error: %w", err)
			}

			return fmt.Errorf("Error editing playlist (%d): %s", errResp.Error.Status, errResp.Error.Message)
		}
		break
	}
	return nil

}

func (s *SpotifyClient) CreatePlaylist(ctx context.Context, playlistInfo PlaylistInfo, oldPlaylistID string, playListCount int) (string, error) {
	RateLimitMultiplier := 1
	if playListCount > 0 {
		playlistInfo.Name = fmt.Sprintf("%s%d", playlistInfo.Name, playListCount)
	}
	jsonData, err := json.Marshal(playlistInfo)
	if err != nil {
		return "", fmt.Errorf("Error marshaling struct: %w", err)
	}

	for {
		requestBody := bytes.NewBuffer(jsonData)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf(s.WebConfig.CreatePlaylistURL, s.ClientID), requestBody)
		if err != nil {

			return "", fmt.Errorf("Error creating the request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+s.Auth.Token.AccessToken)

		req.Header.Set("Content-Type", "application/json")

		resp, err := s.WebConfig.client.Do(req)
		if err != nil {
			return "", fmt.Errorf("Error while doing request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			if resp.StatusCode == 429 {
				rateLimitTime := RateLimitWaitTime * RateLimitMultiplier
				log.Printf("Error while adding to playlist (Rate limit). Trying again in %d seconds...", rateLimitTime)
				time.Sleep(time.Duration(rateLimitTime) * time.Second)
				RateLimitMultiplier++
				continue
			}

			if resp.StatusCode == 502 {
				log.Printf("Error while adding to playlist. Trying again in %d seconds...", 1)
				time.Sleep(1 * time.Second)
				RateLimitMultiplier++
				continue
			}

			var errResp ErrorResponse
			err := json.NewDecoder(resp.Body).Decode(&errResp)
			if err != nil {
				return "", fmt.Errorf("Error decoding JSON error: %w", err)
			}

			return "", fmt.Errorf("Error creating playlist (%d): %s", errResp.Error.Status, errResp.Error.Message)
		}
		var SpotifyID SpotifyPlaylistID
		err = json.NewDecoder(resp.Body).Decode(&SpotifyID)
		if err != nil {
			log.Println("Error retrieving Spotify ID")
			return "", fmt.Errorf("Error decoding JSON error: %w", err)
		}

		log.Println("Playlist Created")
		if playListCount > 0 {
			if oldPlaylistID == "" {
				return "", fmt.Errorf("Old Playlist ID is NULL")
			}
			err = s.EditPlaylistDescription(ctx, SpotifyID.ID, oldPlaylistID)
			if err != nil {
				return "", err
			}

		}
		return SpotifyID.ID, nil
	}

}

func (s *SpotifyClient) AddToPlaylist(ctx context.Context, musicURIS SpotifyAddPlaylist, playlistID string) error {
	jsonData, err := json.Marshal(musicURIS)
	if err != nil {

		return fmt.Errorf("Error While marshaling: %s", err)
	}

	RateLimitMultiplier := 1

	for {
		requestBody := bytes.NewBuffer(jsonData)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf(s.WebConfig.PlaylistURL, playlistID), requestBody)
		if err != nil {
			return fmt.Errorf("Error while creating request: %s", err)
		}

		req.Header.Set("Authorization", "Bearer "+s.Auth.Token.AccessToken)

		req.Header.Set("Content-Type", "application/json")

		resp, err := s.WebConfig.client.Do(req)
		if err != nil {
			return fmt.Errorf("Error while requesting: %s", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode > 300 {
			if resp.StatusCode == 429 {
				rateLimitTime := RateLimitWaitTime * RateLimitMultiplier
				log.Printf("Error while adding to playlist (Rate limit). Trying again in %d seconds...", rateLimitTime)
				time.Sleep(time.Duration(rateLimitTime) * time.Second)
				RateLimitMultiplier++
				continue
			}

			if resp.StatusCode == 502 {
				log.Printf("Error while adding to playlist. Trying again in %d seconds...", 1)
				time.Sleep(1 * time.Second)
				RateLimitMultiplier++
				continue
			}
			var errResp ErrorResponse
			err = json.NewDecoder(resp.Body).Decode(&errResp)
			if err != nil {
				return fmt.Errorf("Error decoding JSON error: %s", err)
			}
			return fmt.Errorf("Error to add music to playlist `%s` (%d): %s", playlistID, errResp.Error.Status, errResp.Error.Message)
		}
		break
	}

	return nil
}

func (s *SpotifyClient) WriterWorker(ctx context.Context, job <-chan WriteJob, writerdictionary map[byte]string, wg *sync.WaitGroup) {
	defer wg.Done()
	for j := range job {
		for i, chunk := range j.Chunks {
			musicsURI := make([]string, len(chunk))
			for idx, b := range chunk {
				musicsURI[idx] = writerdictionary[b]
			}

			addPlaylistURIS := SpotifyAddPlaylist{
				MusicURIS: musicsURI,
			}

			for {
				err := s.AddToPlaylist(ctx, addPlaylistURIS, j.PlaylistID)
				if err == nil {
					break
				}

				log.Printf("[Worker] Critical error adding chunk %d to playlist %s: %v", i, j.PlaylistID, err)
				time.Sleep(1 * time.Second)
			}
		}
		fmt.Printf("Successfully finished all chunks for playlist %s\n", j.PlaylistID)
	}
}

func (s *SpotifyClient) Writer(filepath string, password string, playlistName string) {
	ctx := context.Background()
	writerdictionary, readerdictionary, err := s.NewDictionary(ctx, password)
	if err != nil {
		fmt.Printf("Error initializing dictionary: %v\n", err)
		return
	}

	fmt.Println("Saving map to file...")
	decoderFile := playlistName + "_Decoder.gob"
	if err := saveMap(decoderFile, readerdictionary, password); err != nil {
		fmt.Printf("Error saving decoder map: %v\n", err)
		return
	}

	file, err := os.Open(filepath)
	if err != nil {
		log.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	jobs := make(chan WriteJob, numWorkers)
	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for w := 0; w < numWorkers; w++ {
		go s.WriterWorker(ctx, jobs, writerdictionary, &wg)
	}

	playlistCount := 0
	lastPlaylistID := ""
	var currentChunks [][]byte
	bytesInCurrentPlaylist := 0
	readBuf := make([]byte, SpotifyMaxTracksPerRequest)

	isPublic := true
	pInfo := PlaylistInfo{
		Name:   playlistName,
		Public: &isPublic,
	}

	for {
		n, err := file.Read(readBuf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, readBuf[:n])
			currentChunks = append(currentChunks, chunk)
			bytesInCurrentPlaylist += n
		}

		if (bytesInCurrentPlaylist >= maxBytesPerPlaylist || err == io.EOF) && len(currentChunks) > 0 {
			newPlaylistID, createErr := s.CreatePlaylist(ctx, pInfo, lastPlaylistID, playlistCount)
			if createErr != nil {
				log.Printf("Failed to create playlist %d: %v", playlistCount, createErr)
				break
			}

			jobs <- WriteJob{
				PlaylistID: newPlaylistID,
				Chunks:     currentChunks,
			}

			lastPlaylistID = newPlaylistID
			currentChunks = nil
			bytesInCurrentPlaylist = 0
			playlistCount++
		}

		if err == io.EOF {
			break
		}
	}

	close(jobs)
	fmt.Println("All playlist links created. Finishing track uploads...")
	wg.Wait()
	fmt.Println("All songs were added to the linked playlists successfully.")
}

func (s *SpotifyClient) GetNextPlaylist(ctx context.Context, PlaylistID string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(s.WebConfig.GetPlaylist, PlaylistID), nil)
	if err != nil {
		return "", fmt.Errorf("Error while creating request: %s", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.Auth.Token.AccessToken)

	query := req.URL.Query()
	query.Add("fields", "description")

	req.URL.RawQuery = query.Encode()

	resp, err := s.WebConfig.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Error while requesting: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 300 {
		var errResp ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		if err != nil {
			return "", fmt.Errorf("Error decoding JSON error: %s", err)
		}
		return "", fmt.Errorf("Error to get playlist description `%s` (%d): %s", PlaylistID, errResp.Error.Status, errResp.Error.Message)
	}

	var description PlaylistInfo
	err = json.NewDecoder(resp.Body).Decode(&description)
	if err != nil {
		return "", fmt.Errorf("Error to decode response: %w", err)
	}

	if description.Description == "null" {
		return "", fmt.Errorf("No more playlist, file is complete :)")
	}

	return description.Description, nil
}

func (s *SpotifyClient) ReaderWorker(ctx context.Context, jobs <-chan ReadJob, results chan<- ReadResult, readerdictionary map[string]byte) {
	for j := range jobs {
		playlistURL := fmt.Sprintf(s.WebConfig.PlaylistURL, j.PlaylistID)
		var allBytes []byte
		var nextPlaylistID string

		rateLimitMultiplier := 1

		for {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, playlistURL, nil)
			req.Header.Set("Authorization", "Bearer "+s.Auth.Token.AccessToken)

			query := req.URL.Query()
			query.Add("fields", "next,items(track(uri))")
			query.Add("limit", "50")
			req.URL.RawQuery = query.Encode()

			resp, err := s.WebConfig.client.Do(req)
			if err != nil {
				log.Printf("Request Error: %v. Trying Again", err)
				continue
			}

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				if resp.StatusCode == 429 {
					waitTime := RateLimitWaitTime * rateLimitMultiplier
					log.Printf("[Worker] Rate Limit on playlist %s. Waiting %d seconds...", j.PlaylistID, waitTime)
					time.Sleep(time.Duration(waitTime) * time.Second)
					rateLimitMultiplier++
					resp.Body.Close()
					continue
				}

				if resp.StatusCode == 502 { // Bad Gateway
					log.Printf("[Worker] Error 502 in playlist %s. Trying again in 1s...", j.PlaylistID)
					time.Sleep(1 * time.Second)
					rateLimitMultiplier++
					resp.Body.Close()
					continue
				}

				log.Printf("Fatal error %d playlist %s", resp.StatusCode, j.PlaylistID)
				resp.Body.Close()
				break
			}

			var items PlaylistItems
			json.NewDecoder(resp.Body).Decode(&items)
			resp.Body.Close()

			for _, item := range items.Items {
				if b, ok := readerdictionary[item.Track.Uri]; ok {
					allBytes = append(allBytes, b)
				}
			}

			if items.Next == "" {
				nextID, _ := s.GetNextPlaylist(ctx, j.PlaylistID)
				nextPlaylistID = nextID
				break
			}
			playlistURL = items.Next
		}

		results <- ReadResult{
			Sequence: j.Sequence,
			Data:     allBytes,
			NextID:   nextPlaylistID,
		}
	}
}

func (s *SpotifyClient) Reader(startPlaylistID, filename, password, decoder string) {
	ctx := context.Background()
	var readerdictionary map[string]byte
	var err error

	if decoder == "" {
		_, readerdictionary, err = s.NewDictionary(ctx, password)
	} else {
		readerdictionary, err = loadMap(decoder, password)
	}
	if err != nil {
		log.Fatal(err)
	}

	jobs := make(chan ReadJob, numWorkers)
	results := make(chan ReadResult, numWorkers)

	for w := 0; w < numWorkers; w++ {
		go s.ReaderWorker(ctx, jobs, results, readerdictionary)
	}

	f, _ := os.OpenFile(filename, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()

	pendingResults := make(map[int]ReadResult)
	nextToWrite := 0
	currentPlaylistID := startPlaylistID
	jobsSent := 0

	doneSending := false

	for {
		if !doneSending && len(jobs) < numWorkers && currentPlaylistID != "" {
			jobs <- ReadJob{Sequence: jobsSent, PlaylistID: currentPlaylistID}

			currentPlaylistID, _ = s.GetNextPlaylist(ctx, currentPlaylistID)
			jobsSent++
			if currentPlaylistID == "" {
				doneSending = true
			}
		}

		select {
		case res := <-results:
			pendingResults[res.Sequence] = res
			for {
				if nextRes, ok := pendingResults[nextToWrite]; ok {
					f.Write(nextRes.Data)
					fmt.Printf("Playlist sequence %d written to the file.\n", nextToWrite)
					delete(pendingResults, nextToWrite)
					nextToWrite++

					if doneSending && nextToWrite == jobsSent {
						fmt.Println("Completed!")
						return
					}
				} else {
					break
				}
			}
		case <-time.After(time.Second * 10):
			if doneSending && nextToWrite == jobsSent {
				return
			}
		}
	}
}

func StringInput(question string, answer *string, optional bool) {
	for {
		fmt.Printf("%s", question)
		fmt.Scanln(answer)
		if strings.TrimSpace(*answer) == "" && !optional {
			fmt.Println("Empty answer... Please try again")
			continue
		}
		break
	}
}

func initSpotify() (SpotifyClient, error) {
	authStruct, err := NewAuthHandler()
	if err != nil {
		log.Fatalln(err)
	}
	go authStruct.generateSpotifyAuthLink()

	srv := NewHttpServer(authStruct)
	go func(srv *http.Server) {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error starting server: %s", err)
		}
	}(srv)

	var timeout bool
	select {
	case <-authStruct.Done:
		fmt.Println("Token recived, shuting down server...")
	case <-time.After(1 * time.Minute):
		fmt.Println("Timeout, shuting down server...")
		timeout = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		fmt.Printf("Error to shutdown the web server: %v\n", err)
	} else {
		fmt.Println("Server is shutdown")
	}

	if timeout {
		return SpotifyClient{}, fmt.Errorf("Server shut down due to inactivity (timeout).")
	}

	ctx = context.Background()

	webConfig := WebClient{
		client:           &http.Client{Timeout: 10 * time.Second},
		SpotifySearchURL: "https://api.spotify.com/v1/search",
		SpotifyUserURL:   "https://api.spotify.com/v1/me",

		// The `%s` prefix is required in both URLs because information such as the user ID is needed for the query.
		CreatePlaylistURL:     "https://api.spotify.com/v1/users/%s/playlists",
		PlaylistURL:           "https://api.spotify.com/v1/playlists/%s/tracks",
		ChangePlaylistDetails: "https://api.spotify.com/v1/playlists/%s",
		GetPlaylist:           "https://api.spotify.com/v1/playlists/%s",
	}

	client := SpotifyClient{
		Auth:      authStruct,
		WebConfig: webConfig,
	}

	err = client.GetUserID(ctx)
	if err != nil {
		return SpotifyClient{}, fmt.Errorf("Cannot get user ID: %v", err)
	}

	return client, nil
}

func main() {

	fmt.Printf(` 
                                                                                                      
 @@@@@@   @@@@@@@    @@@@@@   @@@@@@@  @@@  @@@@@@@@  @@@ @@@             @@@@@@@@   @@@@@@   
@@@@@@@   @@@@@@@@  @@@@@@@@  @@@@@@@  @@@  @@@@@@@@  @@@ @@@             @@@@@@@@  @@@@@@@   
!@@       @@!  @@@  @@!  @@@    @@!    @@!  @@!       @@! !@@             @@!       !@@       
!@!       !@!  @!@  !@!  @!@    !@!    !@!  !@!       !@! @!!             !@!       !@!       
!!@@!!    @!@@!@!   @!@  !@!    @!!    !!@  @!!!:!     !@!@!   @!@!@!@!@  @!!!:!    !!@@!!    
 !!@!!!   !!@!!!    !@!  !!!    !!!    !!!  !!!!!:      @!!!   !!!@!@!!!  !!!!!:     !!@!!!   
     !:!  !!:       !!:  !!!    !!:    !!:  !!:         !!:               !!:            !:!  
    !:!   :!:       :!:  !:!    :!:    :!:  :!:         :!:               :!:           !:!   
:::: ::    ::       ::::: ::     ::     ::   ::          ::                ::       :::: ::   
:: : :     :         : :  :      :     :     :           :                 :        :: : :


		`)

	var option int
	for {
		fmt.Printf("Would you like to:\n1) Write file to Playlist\n2) Read file from Playlist\nAnswer:")
		fmt.Scanln(&option)
		if option > 2 {
			fmt.Println("Invalid option... Try again")
			continue
		}
		break
	}

	var secretKey string
	StringInput("Enter password to use as a seed: ", &secretKey, false)

	var filepath string
	var playlistName string
	var playlistID string
	var gobFilePath string
	switch option {
	case 1:
		StringInput("Enter the filepath of the file you would like to store: ", &filepath, false)
		StringInput("Enter a name for the Playlist: ", &playlistName, false)
		client, err := initSpotify()
		if err != nil {
			fmt.Println(err)
			return
		}
		client.Writer(filepath, secretKey, playlistName)

	case 2:
		StringInput("Enter playlist ID: ", &playlistID, false)
		StringInput("Enter a name for the file to be restored, including the extension: ", &filepath, false)
		StringInput("Path to the decoder file (Optional, but recommended): ", &gobFilePath, true)
		client, err := initSpotify()
		if err != nil {
			fmt.Println(err)
			return
		}
		client.Reader(playlistID, filepath, secretKey, gobFilePath)

	default:
	}

}
