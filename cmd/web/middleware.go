package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

func secureHeaders(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Note: This is split across multiple lines for readability. You don't
		// need to do this in your own code.

		//w.Header().Set("Content-Security-Policy",
		//	"default-src 'self'; style-src 'self' fonts.googleapis.com; font-src fonts.gstatic.com; script-src 'self'")

		nonce := generateNonce()
		w.Header().Set("Content-Security-Policy", fmt.Sprintf("script-src 'self' 'nonce-%s'; style-src 'self' fonts.googleapis.com", nonce))
		ctx := context.WithValue(r.Context(), "nonce", nonce)
		r = r.WithContext(ctx)

		w.Header().Set("Referrer-Policy", "origin-when-cross-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "deny")
		w.Header().Set("X-XSS-Protection", "0")
		next.ServeHTTP(w, r)
	})
}
func (app *application) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.infoLog.Printf("%s - %s %s %s", r.RemoteAddr, r.Proto, r.Method, r.URL.RequestURI())
		next.ServeHTTP(w, r)
	})
}

func (app *application) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create a deferred function (which will always be run in the event
		// of a panic as Go unwinds the stack).
		defer func() {
			// Use the builtin recover function to check if there has been a
			// panic or not. If there has...
			if err := recover(); err != nil {
				// Set a "Connection: close" header on the response.
				w.Header().Set("Connection", "close")
				// Call the app.serverError helper method to return a 500
				// Internal Server response.
				app.serverError(w, fmt.Errorf("%s", err))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
func (app *application) requireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !app.isAuthenticated(r) {
			http.Redirect(w, r, "/user/login", http.StatusSeeOther)
			return
		}
		// Otherwise set the "Cache-Control: no-store" header so that pages
		// require authentication are not stored in the users browser cache (or
		// other intermediary cache).
		w.Header().Add("Cache-Control", "no-store")
		// And call the next handler in the chain.
		next.ServeHTTP(w, r)
	})
}

func (app *application) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "Client certificate required", http.StatusUnauthorized)
			return
		}

		clientCert := r.TLS.PeerCertificates[0] // X.509 сертификат клиента

		isUser, err := app.cas[0].findIsUser(clientCert)
		if isUser == nil || err != nil {
			http.Error(w, "Unknown certificate issuer", http.StatusUnauthorized)
			return
		}

		ocspreq, err := ocsp.CreateRequest(clientCert, isUser, &ocsp.RequestOptions{
			Hash: crypto.SHA256,
		})

		if ocspreq == nil || err != nil {
			http.Error(w, "OCSP check failed", http.StatusUnauthorized)
			return
		}

		ocspResp, err := app.ocspCheck(ocspreq, isUser)
		if err != nil {
			app.errorLog.Print(err)
			http.Error(w, "Certificate revoked or OCSP check failed", http.StatusUnauthorized)
			return

		}

		if ocspResp.Status == ocsp.Revoked {
			app.errorLog.Print(err)
			http.Error(w, "Your certificate is revoked", http.StatusUnauthorized)
			return
		}

		if ocspResp.Status == ocsp.Unknown {
			app.errorLog.Print(err)
			http.Error(w, "Your certificate is unknown", http.StatusUnauthorized)
			return
		}

		now := time.Now()
		if now.Before(ocspResp.ThisUpdate) || now.After(ocspResp.NextUpdate) {
			http.Error(w, "Your OCSP is expired", http.StatusUnauthorized)
			return
		}

		// Пример: добавить имя пользователя в контекст
		ctx := context.WithValue(r.Context(), "username", clientCert.Subject.CommonName)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func generateNonce() string {
	nonce := make([]byte, 16) // 16 байт для nonce
	_, err := rand.Read(nonce)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(nonce)
}
