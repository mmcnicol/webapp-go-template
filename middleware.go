package main

import (
	"log"
	"net/http"
)

type Middleware func(http.HandlerFunc) http.HandlerFunc

type GopherMiddleware struct{}

func NewGopherMiddleware() *GopherMiddleware {
	return &GopherMiddleware{}
}

// Chain applies middlewares to a http.HandlerFunc
func (m GopherMiddleware) Chain(f http.HandlerFunc, middlewares ...Middleware) http.HandlerFunc {
	for _, m := range middlewares {
		f = m(f)
	}
	return f
}

func (m GopherMiddleware) JWT() Middleware {

	return func(f http.HandlerFunc) http.HandlerFunc {

		return func(w http.ResponseWriter, r *http.Request) {

			// Get JWT cookie
			cookie, err := r.Cookie("token")
			if err != nil {
				log.Println("error accessing JWT cookie:", err)
				http.Redirect(w, r, "/", http.StatusUnauthorized)
				return
			}

			tokenString := cookie.Value

			j := NewGopherJWT()
			err = j.VerifyToken(tokenString, string(jwtKey[:]))
			if err != nil {
				log.Println("VerifyToken error:", err)
				http.Redirect(w, r, "/", http.StatusUnauthorized)
				return
			}

			log.Println("JWT middleware - token verified")

			// Call the next middleware/handler in chain
			f(w, r)
		}
	}
}

func (m GopherMiddleware) CSRF() Middleware {

	return func(f http.HandlerFunc) http.HandlerFunc {

		return func(w http.ResponseWriter, r *http.Request) {

			err := r.ParseForm()
			if err != nil {
				log.Println("error parsing form:", err)
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			csrfToken := r.FormValue("csrf_token")
			log.Println("CSRF middleware - form CSRF token: ", csrfToken)

			c := NewGopherCSRF()
			cookieToken, err := c.GetCSRFCookie(r)
			if err != nil {
				log.Println("error reading CSRF token from cookie:", err)
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			log.Println("CSRF middleware - cookie CSRF token: ", cookieToken)
			if cookieToken != csrfToken {
				log.Println("CSRF token mismatch")
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			// Call the next middleware/handler in chain
			f(w, r)
		}
	}
}
