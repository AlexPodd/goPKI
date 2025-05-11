package main

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/justinas/alice"
)

// The routes() method returns a servemux containing our application routes.

func (app *application) routes() http.Handler {
	router := httprouter.New()
	router.NotFound = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.notFound(w)
	})

	router.Handler(http.MethodPost, "/api/cert/sign", alice.New().ThenFunc(app.createCertificate))

	//обработка ocsp запросов
	router.Handler(http.MethodPost, "/application/ocsp-request", alice.New().ThenFunc(app.ocsp_server))

	dynamic := alice.New(noSurf, app.authenticate)
	router.Handler(http.MethodGet, "/secure", dynamic.ThenFunc(app.secure))
	router.Handler(http.MethodPost, "/api/ocsp-request/serial", dynamic.ThenFunc(app.ocsp_server_serial))
	//router.Handler(http.MethodPost, "/api/cert/sign", dynamic.ThenFunc(app.createCertificate))

	//protected := dynamic.Append(app.requireAuthentication)
	//router.Handler(http.MethodPost, "/user/logout", protected.ThenFunc(app.userLogoutPost))

	standard := alice.New(app.recoverPanic, app.logRequest, secureHeaders)
	return standard.Then(router)
}
