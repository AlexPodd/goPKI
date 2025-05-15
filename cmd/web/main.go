package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time" // New import

	"github.com/AlexPodd/PKI/internal/models" // New import
	// New import
	"github.com/go-playground/form/v4"
	_ "github.com/go-sql-driver/mysql"
	"github.com/justinas/nosurf"
	"github.com/rs/cors"
)

type certificateAutor struct {
	cert               *x509.Certificate
	privateKey         *rsa.PrivateKey
	trust              []*x509.Certificate
	validateClientDate int
	rootCA             *x509.Certificate
}

type application struct {
	errorLog             *log.Logger
	infoLog              *log.Logger
	users                *models.UserModel
	certificates         *models.CertificateModel
	revoked_certificates *models.RevokedCertificateModel
	formDecoder          *form.Decoder
	cas                  []*certificateAutor
}

type CAKeyConfig struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
	Password string `json:"password"`
}

type AppConfig struct {
	TrustPath             string        `json:"trustPath"`
	KeyPath               string        `json:"keyPath"`
	TlsServerCert         string        `json:"tlsServerCert"`
	TlsServerKey          string        `json:"tlsServerKey"`
	ValidationDays        int           `json:"validationDays"`
	RootCACertificatePath string        `json:"rootCACertificatePath"`
	CAKeys                []CAKeyConfig `json:"caKeys"`
	Database              DBConfig      `json:"database"`
}

type DBConfig struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Name     string `json:"name"`
}

func main() {

	infoLog := log.New(os.Stdout, "INFO\t", log.Ldate|log.Ltime)
	errorLog := log.New(os.Stderr, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)

	config, err := loadConfig("config.json")
	if err != nil {
		errorLog.Fatal("Error loading config: ", err)
	}

	addr := flag.String("addr", ":8081", "HTTP network address")
	//dsn := flag.String("dsn", "root:password@/pki?parseTime=true", "MySQL data source name")
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
		config.Database.User,
		config.Database.Password,
		config.Database.Host,
		config.Database.Port,
		config.Database.Name,
	)
	flag.Parse()

	db, err := openDB(dsn)
	if err != nil {
		errorLog.Fatal(err)
	}
	defer db.Close()
	if err != nil {
		errorLog.Fatal(err)
	}
	// Initialize a decoder instance...
	formDecoder := form.NewDecoder()

	trust, err := loadTrustCertificates(config.TrustPath)
	if err != nil {
		errorLog.Fatal("Error loading trust certificates:", err)
	}

	rootCA, err := LoadCertificateFromFile(config.RootCACertificatePath)
	if err != nil {
		errorLog.Fatal("Error loading root CA:", err)
	}

	cas, err := loadCAFromConfig(config, trust, rootCA)
	if err != nil {
		errorLog.Fatal("Error loading CA:", err)
	}
	app := &application{
		errorLog:             errorLog,
		infoLog:              infoLog,
		users:                &models.UserModel{DB: db},
		certificates:         &models.CertificateModel{DB: db},
		revoked_certificates: &models.RevokedCertificateModel{DB: db},
		formDecoder:          formDecoder,
		cas:                  cas,
	}
	// Initialize a tls.Config struct to hold the non-default TLS settings we
	// want the server to use. In this case the only thing that we're changing
	// is the curve preferences value, so that only elliptic curves with
	// assembly implementations are used.
	tlsConfig := &tls.Config{
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
	// Set the server's TLSConfig field to use the tlsConfig variable we just
	// created.
	handler := app.routes()
	corshandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"https://localhost:3001"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: true,
	}).Handler(handler)

	srv := &http.Server{
		Addr:         *addr,
		ErrorLog:     errorLog,
		Handler:      corshandler,
		TLSConfig:    tlsConfig,
		IdleTimeout:  time.Minute,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	infoLog.Printf("Starting server on %s", *addr)
	err = srv.ListenAndServeTLS(config.TlsServerCert, config.TlsServerKey)
	errorLog.Fatal(err)
}

// The openDB() function wraps sql.Open() and returns a sql.DB connection pool
// for a given DSN.
func openDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}
func noSurf(next http.Handler) http.Handler {
	csrfHandler := nosurf.New(next)
	csrfHandler.SetBaseCookie(http.Cookie{
		HttpOnly: true,
		Path:     "/",
		Secure:   true,
	})
	return csrfHandler
}
