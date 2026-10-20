// SPDX-License-Identifier: Apache-2.0

// mitm-collector-cdh retrieves a CDH dataset and stores encrypted snapshots.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultAMBaseURL  = "https://emea.prod.alpha.sso.cnxgroup.com/auth"
	defaultDatasetURL = "https://api.cnxgroup.net/cdh/dataset-api/v1/v1/metadata/dataset"
	defaultHub        = "global"
	defaultTimeout    = 60 * time.Second
)

var version = "dev"

type jobArgs struct {
	SourceName string `json:"source_name"`
	Topic      string `json:"topic"`
}

type targetDBConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Database string `json:"database"`
	SSLMode  bool   `json:"sslmode"`
	DSN      string `json:"dsn"`
}

type sourceConfig struct {
	AMBaseURL      string `json:"am_base_url"`
	DatasetURL     string `json:"dataset_url"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	DatasetID      string `json:"dataset_id"`
	Hub            string `json:"hub"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type schedulerCredentials struct {
	MasterKey    string `json:"master_key"`
	DBConfigJSON string `json:"db_config_json"`
}

type statusEvent struct {
	RunID     int    `json:"run_id"`
	Type      string `json:"type"`
	Component string `json:"component,omitempty"`
	Status    string `json:"status,omitempty"`
	Message   string `json:"message"`
	Progress  int    `json:"progress,omitempty"`
}

type ipcClient struct {
	socketPath string
	runID      int
	topic      string
	sourceName string
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		log.Printf("CDH collector failed: %v", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	if err := bootstrapSchedulerCredentials(); err != nil {
		return err
	}

	args, err := parseJobArgs()
	if err != nil {
		return err
	}
	ipc := newIPCClient(args)
	ipc.sendStatus("started", "CDH collector started", 0)

	targetConfig, err := loadTargetDBConfig()
	if err != nil {
		return fail(ipc, err)
	}
	kek, err := validateKEK(os.Getenv("MASTER_KEY"))
	if err != nil {
		return fail(ipc, err)
	}

	pool, err := connectTargetDB(ctx, targetConfig)
	if err != nil {
		return fail(ipc, fmt.Errorf("connect to MitM database: %w", err))
	}
	defer pool.Close()
	ipc.sendStatus("connected", "connected to MitM database", 20)

	configPayload, credentialsNonce, dekID, wrappedDEK, err := loadSourceSecrets(ctx, pool, args.SourceName)
	if err != nil {
		return fail(ipc, err)
	}
	dek, err := unwrapDEK(kek, wrappedDEK)
	if err != nil {
		return fail(ipc, fmt.Errorf("unwrap source DEK: %w", err))
	}
	dekGCM, err := newGCM(dek)
	if err != nil {
		return fail(ipc, fmt.Errorf("initialize source DEK: %w", err))
	}
	configBytes, err := decrypt(dekGCM, credentialsNonce, configPayload)
	if err != nil {
		return fail(ipc, fmt.Errorf("decrypt source configuration: %w", err))
	}

	var source sourceConfig
	if err := json.Unmarshal(configBytes, &source); err != nil {
		return fail(ipc, fmt.Errorf("parse source configuration: %w", err))
	}
	if err := source.validate(); err != nil {
		return fail(ipc, err)
	}
	if source.Hub == "" {
		source.Hub = defaultHub
	}
	if source.AMBaseURL == "" {
		source.AMBaseURL = defaultAMBaseURL
	}
	if source.DatasetURL == "" {
		source.DatasetURL = defaultDatasetURL
	}
	ipc.topic = args.Topic
	ipc.sendStatus("connected", "connected to CDH API", 50)

	payload, err := fetchDataset(ctx, source)
	if err != nil {
		return fail(ipc, err)
	}
	cursor := snapshotCursor(payload)
	lastCursor, err := loadCursor(ctx, pool, args.SourceName)
	if err != nil {
		return fail(ipc, err)
	}
	if cursor == lastCursor {
		ipc.sendAudit("dataset snapshot is unchanged; no record ingested")
		ipc.sendAudit(fmt.Sprintf("mitm-collector-cdh (%s) finished", releaseVersion()))
		return nil
	}

	ipc.sendStatus("processing", "encrypting and ingesting CDH dataset snapshot", 70)
	nonce, err := randomNonce(dekGCM)
	if err != nil {
		return fail(ipc, err)
	}
	encryptedPayload := dekGCM.Seal(nil, nonce, payload, nil)
	correlationID := uuid.NewSHA1(
		uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
		[]byte(source.DatasetID),
	)
	if err := ingestSnapshot(
		ctx, pool, args, correlationID, encryptedPayload, nonce, dekID, cursor,
	); err != nil {
		return fail(ipc, err)
	}

	ipc.sendAudit(fmt.Sprintf("ingested 1 dataset snapshot; cursor=%s", cursor))
	ipc.sendAudit(fmt.Sprintf("mitm-collector-cdh (%s) finished", releaseVersion()))
	return nil
}

func parseJobArgs() (jobArgs, error) {
	args := jobArgs{Topic: "cdh.dataset.data"}
	if len(os.Args) > 1 && os.Args[1] != "" {
		if err := json.Unmarshal([]byte(os.Args[1]), &args); err != nil {
			return jobArgs{}, fmt.Errorf("parse job arguments: %w", err)
		}
	}
	if strings.TrimSpace(args.SourceName) == "" {
		return jobArgs{}, errors.New("source_name is required in the collector job arguments")
	}
	if strings.TrimSpace(args.Topic) == "" {
		return jobArgs{}, errors.New("topic must not be empty")
	}
	return args, nil
}

func (c sourceConfig) validate() error {
	switch {
	case strings.TrimSpace(c.ClientID) == "":
		return errors.New("source configuration is missing client_id")
	case strings.TrimSpace(c.ClientSecret) == "":
		return errors.New("source configuration is missing client_secret")
	case strings.TrimSpace(c.DatasetID) == "":
		return errors.New("source configuration is missing dataset_id")
	case c.TimeoutSeconds < 0:
		return errors.New("source configuration timeout_seconds must not be negative")
	default:
		return nil
	}
}

func bootstrapSchedulerCredentials() error {
	runID, socketPath := os.Getenv("RUN_ID"), os.Getenv("SCHEDULER_SOCKET_PATH")
	if runID == "" && socketPath == "" {
		return nil
	}
	if runID == "" || socketPath == "" {
		return errors.New("RUN_ID and SCHEDULER_SOCKET_PATH must both be set")
	}
	credentials, err := fetchSchedulerCredentials(runID, socketPath)
	if err != nil {
		return fmt.Errorf("fetch scheduler credentials: %w", err)
	}
	if credentials.DBConfigJSON == "" || credentials.MasterKey == "" {
		return errors.New("scheduler returned incomplete credentials")
	}
	if err := os.Setenv("MITM_DB_CONFIG_JSON", credentials.DBConfigJSON); err != nil {
		return err
	}
	return os.Setenv("MASTER_KEY", credentials.MasterKey)
}

func fetchSchedulerCredentials(runIDText, socketPath string) (schedulerCredentials, error) {
	runID, err := strconv.Atoi(runIDText)
	if err != nil {
		return schedulerCredentials{}, fmt.Errorf("parse RUN_ID: %w", err)
	}
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return schedulerCredentials{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return schedulerCredentials{}, err
	}
	request, err := json.Marshal(map[string]any{"type": "get_credentials", "run_id": runID})
	if err != nil {
		return schedulerCredentials{}, err
	}
	if _, err := conn.Write(append(request, '\n')); err != nil {
		return schedulerCredentials{}, err
	}
	var response schedulerCredentials
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&response); err != nil {
		return schedulerCredentials{}, err
	}
	return response, nil
}

func newIPCClient(args jobArgs) *ipcClient {
	runID, err := strconv.Atoi(os.Getenv("RUN_ID"))
	if err != nil || os.Getenv("SCHEDULER_SOCKET_PATH") == "" {
		return nil
	}
	return &ipcClient{
		socketPath: os.Getenv("SCHEDULER_SOCKET_PATH"),
		runID:      runID, topic: args.Topic, sourceName: args.SourceName,
	}
}

func (c *ipcClient) sendStatus(status, message string, progress int) {
	if c == nil {
		return
	}
	c.send(statusEvent{RunID: c.runID, Type: "status", Status: status, Message: c.message(message), Progress: progress})
}

func (c *ipcClient) sendAudit(message string) {
	if c == nil {
		return
	}
	c.send(statusEvent{RunID: c.runID, Type: "audit", Component: "mitm_collector_cdh", Message: c.message(message)})
}

func (c *ipcClient) message(message string) string {
	return fmt.Sprintf("%s: %s: %s", c.topic, c.sourceName, message)
}

func (c *ipcClient) send(event statusEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("serialize IPC event: %v", err)
		return
	}
	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		log.Printf("connect to scheduler for IPC event: %v", err)
		return
	}
	defer conn.Close()
	if _, err := conn.Write(append(data, '\n')); err != nil {
		log.Printf("send IPC event: %v", err)
	}
}

func loadTargetDBConfig() (targetDBConfig, error) {
	var config targetDBConfig
	if rawConfig := os.Getenv("MITM_DB_CONFIG_JSON"); rawConfig != "" {
		var wrapped struct {
			DB targetDBConfig `json:"db"`
		}
		if err := json.Unmarshal([]byte(rawConfig), &wrapped); err != nil {
			return targetDBConfig{}, fmt.Errorf("parse MITM_DB_CONFIG_JSON: %w", err)
		}
		config = wrapped.DB
	}
	if config.Host == "" {
		config.Host = os.Getenv("MITM_DB_HOST")
		config.User = os.Getenv("MITM_DB_USER")
		config.Password = os.Getenv("MITM_DB_PASSWORD")
		config.Database = os.Getenv("MITM_DB_DATABASE")
		config.DSN = os.Getenv("MITM_DB_DSN")
		if port, err := strconv.Atoi(os.Getenv("MITM_DB_PORT")); err == nil {
			config.Port = port
		}
		config.SSLMode, _ = strconv.ParseBool(os.Getenv("MITM_DB_SSLMODE"))
	}
	if config.DSN == "" && (config.Host == "" || config.User == "" || config.Database == "") {
		return targetDBConfig{}, errors.New("MitM database configuration is incomplete")
	}
	return config, nil
}

func connectTargetDB(ctx context.Context, config targetDBConfig) (*pgxpool.Pool, error) {
	dsn := config.DSN
	if dsn == "" {
		sslMode := "disable"
		if config.SSLMode {
			sslMode = "require"
		}
		dsn = fmt.Sprintf(
			"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			config.Host, config.Port, config.User, config.Password, config.Database, sslMode,
		)
	}
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	poolConfig.MaxConns = 20
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.MaxConnLifetime = time.Hour
	return pgxpool.NewWithConfig(ctx, poolConfig)
}

func validateKEK(masterKey string) ([]byte, error) {
	if masterKey == "" {
		return nil, errors.New("MASTER_KEY is required")
	}
	if decoded, err := base64.StdEncoding.DecodeString(masterKey); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("MASTER_KEY must be exactly 32 bytes, got %d", len(masterKey))
	}
	return []byte(masterKey), nil
}

func loadSourceSecrets(ctx context.Context, pool *pgxpool.Pool, sourceName string) ([]byte, []byte, uuid.UUID, []byte, error) {
	var configPayload, nonce, wrappedDEK []byte
	var dekID uuid.UUID
	err := pool.QueryRow(ctx, `
		SELECT sc.config_payload, sc.nonce, sc.dek_id, sk.wrapped_key
		FROM source_credentials sc
		JOIN storage_keys sk ON sk.id = sc.dek_id
		WHERE sc.source_name = $1 AND sc.is_active = true AND sk.is_active = true
		LIMIT 1
	`, sourceName).Scan(&configPayload, &nonce, &dekID, &wrappedDEK)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, uuid.Nil, nil, fmt.Errorf("no active credentials for source %q", sourceName)
		}
		return nil, nil, uuid.Nil, nil, fmt.Errorf("load source credentials: %w", err)
	}
	return configPayload, nonce, dekID, wrappedDEK, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func unwrapDEK(kek, wrappedDEK []byte) ([]byte, error) {
	kekGCM, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	return decryptPrefixedNonce(kekGCM, wrappedDEK)
}

func decryptPrefixedNonce(gcm cipher.AEAD, encrypted []byte) ([]byte, error) {
	if len(encrypted) < gcm.NonceSize() {
		return nil, errors.New("encrypted value is shorter than its nonce")
	}
	return gcm.Open(nil, encrypted[:gcm.NonceSize()], encrypted[gcm.NonceSize():], nil)
}

func decrypt(gcm cipher.AEAD, nonce, encrypted []byte) ([]byte, error) {
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length %d", len(nonce))
	}
	return gcm.Open(nil, nonce, encrypted, nil)
}

func fetchDataset(ctx context.Context, config sourceConfig) ([]byte, error) {
	timeout := defaultTimeout
	if config.TimeoutSeconds > 0 {
		timeout = time.Duration(config.TimeoutSeconds) * time.Second
	}
	client := &http.Client{Timeout: timeout}
	token, err := requestAccessToken(ctx, client, config)
	if err != nil {
		return nil, err
	}
	datasetURL, err := url.Parse(config.DatasetURL)
	if err != nil {
		return nil, fmt.Errorf("parse dataset URL: %w", err)
	}
	query := datasetURL.Query()
	query.Set("dataset_id", config.DatasetID)
	query.Set("hub", config.Hub)
	datasetURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, datasetURL.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request CDH dataset: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("CDH dataset request returned HTTP %d", response.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 100<<20))
	if err != nil {
		return nil, fmt.Errorf("read CDH dataset response: %w", err)
	}
	if !json.Valid(payload) {
		return nil, errors.New("CDH dataset response is not valid JSON")
	}
	return payload, nil
}

func requestAccessToken(ctx context.Context, client *http.Client, config sourceConfig) (string, error) {
	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"machine2machine client_" + config.ClientID},
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		strings.TrimRight(config.AMBaseURL, "/")+"/oauth2/realms/root/realms/alpha/access_token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.SetBasicAuth(config.ClientID, config.ClientSecret)
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("request CDH access token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("CDH access-token request returned HTTP %d", response.StatusCode)
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&token); err != nil {
		return "", fmt.Errorf("decode CDH access-token response: %w", err)
	}
	if token.AccessToken == "" {
		return "", errors.New("CDH access-token response does not contain access_token")
	}
	return token.AccessToken, nil
}

func snapshotCursor(payload []byte) string {
	hash := sha256.Sum256(bytes.TrimSpace(payload))
	return hex.EncodeToString(hash[:])
}

func loadCursor(ctx context.Context, pool *pgxpool.Pool, sourceName string) (string, error) {
	var cursor string
	err := pool.QueryRow(ctx,
		"SELECT last_cursor FROM ingestion_cursors WHERE source_name = $1", sourceName,
	).Scan(&cursor)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("load ingestion cursor: %w", err)
	}
	return cursor, nil
}

func randomNonce(gcm cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, gcm.NonceSize())
	_, err := io.ReadFull(rand.Reader, nonce)
	return nonce, err
}

func ingestSnapshot(
	ctx context.Context, pool *pgxpool.Pool, args jobArgs, correlationID uuid.UUID,
	payload, nonce []byte, dekID uuid.UUID, cursor string,
) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin ingestion transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO raw_ingestion
			(topic, source_system, correlation_id, payload, nonce, dek_id, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending')
	`, args.Topic, args.SourceName, correlationID, payload, nonce, dekID); err != nil {
		return fmt.Errorf("insert raw ingestion record: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO ingestion_cursors (source_name, last_cursor, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (source_name)
		DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()
	`, args.SourceName, cursor); err != nil {
		return fmt.Errorf("update ingestion cursor: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit ingestion transaction: %w", err)
	}
	return nil
}

func releaseVersion() string {
	return strings.Split(version, "-")[0]
}

func fail(ipc *ipcClient, err error) error {
	ipc.sendStatus("failed", "collector failed; see collector logs for details", 0)
	return err
}
