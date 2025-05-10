package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const rateLimitPeriodS = 3600

type Mirror struct {
	mutex         sync.Mutex
	cacheDir      string
	failedFetches map[string]int64
}

func NewMirror(cacheDir string) (*Mirror, error) {
	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, err
	}

	return &Mirror{
		cacheDir:      cacheDir,
		failedFetches: make(map[string]int64),
	}, nil
}

func (m *Mirror) rateLimitFailedFetch(url string) error {
	timestamp, exists := m.failedFetches[url]
	if !exists {
		return nil
	}

	now := time.Now().Unix()
	if now-timestamp < rateLimitPeriodS {
		log.Println("rate limiting failed fetch")
		return fmt.Errorf("not found")
	}

	delete(m.failedFetches, url)
	return nil
}

func (m *Mirror) setFailedFetch(url string) {
	now := time.Now().Unix()
	m.failedFetches[url] = now
}

func (m *Mirror) getAtpack(atpackName string) ([]byte, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Try to read from cache first
	filePath := filepath.Join(m.cacheDir, atpackName)
	data, err := os.ReadFile(filePath)
	if err == nil {
		return data, nil
	}

	// If not in cache, fetch from remote
	url := fmt.Sprintf("http://packs.download.atmel.com/%s", atpackName)
	if err := m.rateLimitFailedFetch(url); err != nil {
		return nil, err
	}

	log.Printf("making request to %s", url)
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("Failed to fetch '%s': %v", url, err)
		return nil, err
	}
	defer resp.Body.Close()

	log.Printf("result: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		m.setFailedFetch(url)
		return nil, fmt.Errorf("not found")
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v", err)
		return nil, err
	}

	// Write to cache file
	if err := os.WriteFile(filePath, body, 0644); err != nil {
		log.Printf("Failed to write file '%s': %v", atpackName, err)
		// Continue even if caching fails
	}

	return body, nil
}

func getAtpackHandler(mirror *Mirror) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		log.Printf("path: %s", path)

		// Check if path has more than one segment
		if strings.Contains(path, "/") {
			http.NotFound(w, r)
			return
		}

		// Check if file has .atpack extension
		if !strings.HasSuffix(path, ".atpack") {
			http.NotFound(w, r)
			return
		}

		log.Printf("atpack: %s", path)
		body, err := mirror.getAtpack(path)
		if err != nil {
			if err.Error() == "not found" {
				http.NotFound(w, r)
			} else {
				http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			}
			return
		}

		w.Header().Set("Content-Type", "application/zip")
		w.Write(body)
	}
}

func main() {
	mirror, err := NewMirror("./atpack-cache")
	if err != nil {
		log.Fatalf("Failed to initialize mirror: %v", err)
	}

	http.HandleFunc("/", getAtpackHandler(mirror))

	log.Println("Starting server on :3000")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
