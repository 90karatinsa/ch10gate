package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v3"

	"example.com/ch10gate/internal/server"
	"example.com/ch10gate/internal/update"
)

type logConfig struct {
	Directory  string `yaml:"directory"`
	MaxSizeMB  int    `yaml:"maxSizeMB"`
	MaxAgeDays int    `yaml:"maxAgeDays"`
	MaxBackups int    `yaml:"maxBackups"`
	Compress   bool   `yaml:"compress"`
}

type config struct {
	Port            int                   `yaml:"port"`
	StorageDir      string                `yaml:"storageDir"`
	Concurrency     int                   `yaml:"concurrency"`
	ProfileManifest string                `yaml:"profileManifest"`
	ManifestSigning manifestSigningConfig `yaml:"manifestSigning"`
	Profiles        []profileConfig       `yaml:"profiles"`
	Lang            string                `yaml:"lang"`
	Logs            logConfig             `yaml:"logs"`
}

type manifestSigningConfig struct {
	PrivateKey  string `yaml:"privateKey"`
	Certificate string `yaml:"certificate"`
}

type profileConfig struct {
	ID        string `yaml:"id"`
	Name      string `yaml:"name"`
	Rules     string `yaml:"rules"`
	Signature string `yaml:"signature"`
}

func loadConfig(path string) (config, error) {
	var cfg config
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	baseDir := filepath.Dir(path)
	resolvePath := func(p string) string {
		p = strings.TrimSpace(p)
		if p == "" {
			return ""
		}
		if filepath.IsAbs(p) {
			return filepath.Clean(p)
		}
		candidate := filepath.Clean(filepath.Join(baseDir, p))
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		return filepath.Clean(p)
	}
	if cfg.Port == 0 {
		cfg.Port = 8080
	}
	if cfg.StorageDir == "" {
		cfg.StorageDir = filepath.Join(".", "data")
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = runtime.NumCPU()
	}
	cfg.ProfileManifest = resolvePath(cfg.ProfileManifest)
	if cfg.ProfileManifest == "" {
		cfg.ProfileManifest = resolvePath(filepath.Join("..", "profiles", "index.json"))
	}
	cfg.ManifestSigning.PrivateKey = resolvePath(cfg.ManifestSigning.PrivateKey)
	cfg.ManifestSigning.Certificate = resolvePath(cfg.ManifestSigning.Certificate)
	if len(cfg.Profiles) == 0 {
		if cfg.ProfileManifest == "" {
			return cfg, errors.New("no profile manifest configured")
		}
		packs, err := server.LoadProfileManifest(cfg.ProfileManifest)
		if err != nil {
			return cfg, err
		}
		for _, pack := range packs {
			cfg.Profiles = append(cfg.Profiles, profileConfig{
				ID:        pack.ID,
				Name:      pack.Name,
				Rules:     pack.Rules,
				Signature: pack.Signature,
			})
		}
	} else {
		for i := range cfg.Profiles {
			cfg.Profiles[i].Rules = resolvePath(cfg.Profiles[i].Rules)
			cfg.Profiles[i].Signature = resolvePath(cfg.Profiles[i].Signature)
		}
	}
	if len(cfg.Profiles) == 0 {
		return cfg, errors.New("no profiles configured")
	}
	if cfg.Lang == "" {
		cfg.Lang = "en_US.UTF-8"
	}
	if cfg.Logs.Directory == "" {
		cfg.Logs.Directory = filepath.Join(cfg.StorageDir, "logs")
	}
	if cfg.Logs.MaxSizeMB <= 0 {
		cfg.Logs.MaxSizeMB = 25
	}
	if cfg.Logs.MaxAgeDays <= 0 {
		cfg.Logs.MaxAgeDays = 7
	}
	if cfg.Logs.MaxBackups <= 0 {
		cfg.Logs.MaxBackups = 5
	}
	return cfg, nil
}

func setupLogging(cfg config) error {
	if err := os.MkdirAll(cfg.Logs.Directory, 0o755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}
	logFile := filepath.Join(cfg.Logs.Directory, "ch10d.log")
	rotator := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    cfg.Logs.MaxSizeMB,
		MaxAge:     cfg.Logs.MaxAgeDays,
		MaxBackups: cfg.Logs.MaxBackups,
		Compress:   cfg.Logs.Compress,
	}
	log.SetOutput(io.MultiWriter(os.Stdout, rotator))
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	return nil
}

func main() {
	configPath := flag.String("config", "config/config.yaml", "path to configuration file")
	addr := flag.String("addr", "", "listen address (overrides config port)")
	readTimeout := flag.Duration("read-timeout", 60*time.Second, "HTTP read timeout")
	writeTimeout := flag.Duration("write-timeout", 60*time.Second, "HTTP write timeout")
	enableAdmin := flag.Bool("enable-admin", false, "enable administrative endpoints")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := os.MkdirAll(cfg.StorageDir, 0o755); err != nil {
		log.Fatalf("storage dir: %v", err)
	}
	if err := setupLogging(cfg); err != nil {
		log.Fatalf("setup logging: %v", err)
	}
	if cfg.Lang != "" {
		if err := os.Setenv("LANG", cfg.Lang); err != nil {
			log.Printf("set LANG: %v", err)
		}
	}
	listenAddr := fmt.Sprintf(":%d", cfg.Port)
	if *addr != "" {
		listenAddr = *addr
	}
	var updater *update.Installer
	if *enableAdmin {
		updater, err = update.NewInstaller(update.Options{})
		if err != nil {
			log.Fatalf("update init: %v", err)
		}
	}
	packs := make([]server.ProfilePack, len(cfg.Profiles))
	for i, pack := range cfg.Profiles {
		packs[i] = server.ProfilePack{
			ID:        pack.ID,
			Name:      pack.Name,
			Rules:     pack.Rules,
			Signature: pack.Signature,
		}
	}
	srv, err := server.NewServer(server.Options{
		StorageDir:      cfg.StorageDir,
		ProfileManifest: cfg.ProfileManifest,
		ProfilePacks:    packs,
		ManifestSigning: server.ManifestSigningOptions{
			PrivateKeyPath:  cfg.ManifestSigning.PrivateKey,
			CertificatePath: cfg.ManifestSigning.Certificate,
		},
		Concurrency:     cfg.Concurrency,
		EnableAdmin:     *enableAdmin,
		UpdateInstaller: updater,
	})
	if err != nil {
		log.Fatalf("server init: %v", err)
	}
	defer srv.Close()

	router, err := server.NewRouter(srv)
	if err != nil {
		log.Fatalf("router init: %v", err)
	}
	httpServer := &http.Server{
		Addr:         listenAddr,
		Handler:      router,
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
	}

	log.Printf("ch10d listening on %s", listenAddr)
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	log.Println("ch10d stopped")
}
