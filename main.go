package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sethvargo/go-envconfig"
	"golang.org/x/crypto/acme/autocert"
)

const rateLimitPeriodS = 3600

type Config struct {
	CertsPath string `env:"CERTS_PATH"`
	CachePath string `env:"CACHE_PATH"`
	LogLevel  string `env:"LOG_LEVEL"`
	Domain    string `env:"DOMAIN"`
	Host      string `env:"HOST"`
	Port      uint16 `env:"PORT"`
}

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
		log.Error().Msg("rate limiting failed fetch")
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

func getAtpackHandler(mirror *Mirror) gin.HandlerFunc {
	return func(c *gin.Context) {
		atpack := c.Param("atpack")

		// Check if file has .atpack extension
		if !strings.HasSuffix(atpack, ".atpack") {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		log.Info().Str("atpack", atpack).Msg("Fetching atpack")
		body, err := mirror.getAtpack(atpack)
		if err != nil {
			if err.Error() == "not found" {
				c.AbortWithStatus(http.StatusNotFound)
			} else {
				c.AbortWithStatus(http.StatusServiceUnavailable)
			}
			return
		}

		c.Header("Content-Type", "application/zip")
		c.Data(http.StatusOK, "application/zip", body)

	}
}

func main() {
	ctx := context.Background()
	var config Config
	if err := envconfig.Process(ctx, &config); err != nil {
		log.Fatal().Err(err).Msg("Failed to get config env vars")
	}

	log.Info().Interface("config", config).Msg("got config")

	level, err := zerolog.ParseLevel(config.LogLevel)
	if err != nil {
		log.Fatal().Err(err).Str("level", config.LogLevel).Msg("Failed to parse log level")
	}

	log.Logger = log.Level(level)

	mirror, err := NewMirror(config.CachePath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize mirror")
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(ZerologLogger("mirror"))
	router.GET("/:atpack", getAtpackHandler(mirror))

	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)

	log.Info().Str("domain", config.Domain).Msg("setting whitelist")
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(config.CertsPath),
		HostPolicy: autocert.HostWhitelist(config.Domain),
	}

	tlsConfig := &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}

	httpServer := &http.Server{
		Addr:    ":80",
		Handler: m.HTTPHandler(http.HandlerFunc(redirectToHTTPS)),
	}

	httpsServer := &http.Server{
		Addr:      addr,
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	// Start HTTP server in a goroutine
	go func() {
		log.Info().Msg("Starting HTTP server on :80")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("HTTP server error")
		}
	}()

	// Start HTTPS server
	log.Info().Str("addr", httpsServer.Addr).Msg("Starting HTTPS server")
	if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatal().Err(err).Msg("HTTPS server error")
	}
}

func ZerologLogger(handler string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Gather fields to log
		status := c.Writer.Status()
		method := c.Request.Method
		path := c.Request.URL.Path
		clientIP := c.ClientIP()

		// Log with zerolog
		log.Info().
			Str("handler", handler).
			Str("client_ip", clientIP).
			Str("method", method).
			Str("path", path).
			Int("status", status).
			Dur("latency", latency).
			Msg("request completed")
	}
}

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}
