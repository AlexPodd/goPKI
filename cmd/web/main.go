package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
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

func main() {
	addr := flag.String("addr", ":8081", "HTTP network address")
	dsn := flag.String("dsn", "root:podushko2004#@/pki?parseTime=true", "MySQL data source name")
	flag.Parse()
	infoLog := log.New(os.Stdout, "INFO\t", log.Ldate|log.Ltime)
	errorLog := log.New(os.Stderr, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)

	db, err := openDB(*dsn)
	if err != nil {
		errorLog.Fatal(err)
	}
	defer db.Close()
	if err != nil {
		errorLog.Fatal(err)
	}
	// Initialize a decoder instance...
	formDecoder := form.NewDecoder()

	//Срок сертификации
	validateClientDate := 180

	var ca1, ca2, root *x509.Certificate
	var key1, key2 *rsa.PrivateKey
	var trust []*x509.Certificate

	ca1, err = LoadCertificateFromFile("./trustCertificate/intermediate.crt")
	ca2, err = LoadCertificateFromFile("./trustCertificate/intermediate1.crt")
	root, err = LoadCertificateFromFile("./trustCertificate/ca.crt")

	key1, err = LoadPrivateKeyFromFile("./keys/intermediateCA.key")
	key2, err = LoadPrivateKeyFromFile("./keys/intermediateCA1.key")

	trust = append(trust, ca1, ca2, root)

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(ca1)
	caCertPool.AddCert(ca2)
	caCertPool.AddCert(root)

	ca1Class := &certificateAutor{
		cert:               ca1,
		privateKey:         key1,
		trust:              trust,
		validateClientDate: validateClientDate,
	}

	ca2Class := &certificateAutor{
		cert:               ca2,
		privateKey:         key2,
		trust:              trust,
		validateClientDate: validateClientDate,
	}

	var cas []*certificateAutor

	cas = append(cas, ca1Class, ca2Class)

	if err != nil {
		errorLog.Print(err.Error())
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
		ClientAuth:       tls.RequestClientCert,
	}
	// Set the server's TLSConfig field to use the tlsConfig variable we just
	// created.
	handler := app.routes()
	corshandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3001"},
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
	err = srv.ListenAndServeTLS("./tls/serverTLS.crt", "./tls/keyTLS.pem")
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
