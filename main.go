package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// var jwtKey = []byte("your-secret-key")
var jwtKey = []byte{}

type Claims struct {
	Username    string          `json:"Username"`
	Permissions map[string]bool `json:"Permissions"`
	GopherId    string          `json:"GopherId"`
	jwt.RegisteredClaims
}

type Middleware func(http.HandlerFunc) http.HandlerFunc

var tmpl *template.Template

type GopherDemographics struct {
	GopherId    string
	Name        string
	DateOfBirth time.Time
}

type Navigation struct {
	Page     string
	Endpoint string
}

type PageData struct {
	LoggedIn      bool
	Username      string
	Token         string
	GopherDemographics GopherDemographics
	Navigation    []Navigation
	SearchResults []string
	RecentGophers []string
	Documents     []string
	LabResults    []string
}

type LoginPageData struct {
	Username string
	Password string
	Error    string
	Token    string
}

func init() {
	var err error
	tmpl, err = template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatal("Error loading templates:" + err.Error())
	}
}

func main() {

	secret, err := generateRandomSecret(32) // 32 bytes = 256 bits
	if err != nil {
		fmt.Println("Error generating secret:", err)
		return
	}

	fmt.Println("Generated Secret Key:", secret)
	jwtKey = []byte(secret)

	http.HandleFunc("GET /", handleLogin)
	http.HandleFunc("POST /", Chain(handleLogin, CSRF()))
	http.HandleFunc("GET /dashboard", Chain(handleDashboard, JWT()))
	http.HandleFunc("GET /documents", Chain(handleDocuments, JWT()))
	http.HandleFunc("GET /results", Chain(handleResults, JWT()))
	http.HandleFunc("POST /search", Chain(handleSearch, JWT(), CSRF()))
	fmt.Println("Server listening on :8080")
	http.ListenAndServe(":8080", nil)
}

func JWT() Middleware {

	return func(f http.HandlerFunc) http.HandlerFunc {

		return func(w http.ResponseWriter, r *http.Request) {

			//claims, err := verifyToken(r)
			_, err := verifyToken(r)
			if err != nil {
				log.Println("JWT middleware - token verification failed")
				http.Redirect(w, r, "/", http.StatusUnauthorized)
				return
			}

			log.Println("JWT middleware - token verified")

			// Call the next middleware/handler in chain
			f(w, r)
		}
	}
}

func CSRF() Middleware {

	return func(f http.HandlerFunc) http.HandlerFunc {

		return func(w http.ResponseWriter, r *http.Request) {

			err := r.ParseForm()
			if err != nil {
				fmt.Println("error parsing form:", err)
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			csrfToken := r.FormValue("csrf_token")
			log.Println("CSRF middleware - form CSRF token: ", csrfToken)

			cookieToken, err := getCSRFCookie(r)
			if err != nil {
				fmt.Println("error reading CSRF token from cookie:", err)
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			log.Println("CSRF middleware - cookie CSRF token: ", cookieToken)
			if cookieToken != csrfToken {
				fmt.Println("CSRF token mismatch")
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			// Call the next middleware/handler in chain
			f(w, r)
		}
	}
}

// Chain applies middlewares to a http.HandlerFunc
func Chain(f http.HandlerFunc, middlewares ...Middleware) http.HandlerFunc {
	for _, m := range middlewares {
		f = m(f)
	}
	return f
}

func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	token := base64.StdEncoding.EncodeToString(b)
	return token, nil
}

func setCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
	})
}

func getCSRFCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("csrf_token")
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func generateRandomSecret(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

func createToken(username string, permissions map[string]bool) (string, error) {

	// Create JWT claims
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username:    username,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Create the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		fmt.Println("error signing JWT")
		//http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return "", err
	}

	return tokenString, nil
}

func createTokenWithGopherId(username string, permissions map[string]bool, gopherId string) (string, error) {

	// Create JWT claims
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username:    username,
		Permissions: permissions,
		GopherId:    gopherId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Create the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		fmt.Println("error signing JWT")
		//http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return "", err
	}

	return tokenString, nil
}

func verifyToken(r *http.Request) (*Claims, error) {
	cookie, err := r.Cookie("token")
	if err != nil {
		return nil, err
	}

	tokenString := cookie.Value

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func sanitizeUserInput(input string) string {

	sanitized := html.EscapeString(input)
	//sanitized = strings.ReplaceAll(sanitized, "<", "&lt;")
	//sanitized = strings.ReplaceAll(sanitized, ">", "&gt;")
	sanitized = strings.TrimSpace(sanitized)
	maxLength := 1000
	if len(sanitized) > maxLength {
		sanitized = sanitized[:maxLength]
	}
	return sanitized
}

func getNavigation(gopherContext bool) []Navigation {
	if gopherContext {
		return []Navigation{
			{Page: "Home", Endpoint: "/"},
			{Page: "Documents", Endpoint: "/documents"},
			{Page: "Results", Endpoint: "/results"},
		}
	} else {
		return []Navigation{
			{Page: "Home", Endpoint: "/"},
		}
	}
}

func getGopherDemographics(gopherId string) (GopherDemographics, error) {
	switch(gopherId) {
	case "1":
		return GopherDemographics{
			GopherId: "1",
			Name: "Gopher A",
			DateOfBirth: time.Date(1999, 1, 2, 0, 0, 0, 0, time.Local),
		}, nil
	case "2":
		return GopherDemographics{
			GopherId: "2",
			Name: "Gopher B",
			DateOfBirth: time.Date(2000, 2, 3, 0, 0, 0, 0, time.Local),
		}, nil
	case "3":
		return GopherDemographics{
			GopherId: "3",
			Name: "Gopher C",
			DateOfBirth: time.Date(2001, 3, 4, 0, 0, 0, 0, time.Local),
		}, nil
	default: 
		//return GopherDemographics{}, nil
		return GopherDemographics{}, errors.New("gopherId not found")
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {

	fmt.Println("in handleLogin()")

	if r.Method == http.MethodGet {

		token, err := generateCSRFToken()
		if err != nil {
			fmt.Println("CSRF token generation error:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		fmt.Println("GET - created CSRF token: ", token)
		setCSRFCookie(w, token)

		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			fmt.Println("template parsing error:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		data := LoginPageData{ // Initial empty form
			Token: token,
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			fmt.Println("template execution error:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		return
	}

	if r.Method == http.MethodPost {

		err := r.ParseForm()
		if err != nil {
			fmt.Println("error parsing form:", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		usernameSanitized := sanitizeUserInput(username)
		passwordSanitized := sanitizeUserInput(password)

		// Validation logic
		if len(usernameSanitized) < 4 || len(usernameSanitized) > 20 {

			token, err := generateCSRFToken()
			if err != nil {
				fmt.Println("CSRF token generation error:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			fmt.Println("created CSRF token: ", token)
			setCSRFCookie(w, token)

			tmpl, err := template.ParseFiles("login.html")
			if err != nil {
				fmt.Println("template parsing error:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			err = tmpl.Execute(w, LoginPageData{
				Username: usernameSanitized,
				Password: passwordSanitized,
				Error:    "login invalid",
				Token:    token,
			})
			if err != nil {
				fmt.Println("template execution error:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			return
		}

		if len(passwordSanitized) < 4 || len(passwordSanitized) > 20 {

			token, err := generateCSRFToken()
			if err != nil {
				fmt.Println("CSRF token generation error:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			fmt.Println("created CSRF token: ", token)
			setCSRFCookie(w, token)

			tmpl, err := template.ParseFiles("login.html")
			if err != nil {
				fmt.Println("template parsing error:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			err = tmpl.Execute(w, LoginPageData{
				Username: usernameSanitized,
				Password: passwordSanitized,
				Error:    "login invalid",
				Token:    token,
			})
			if err != nil {
				fmt.Println("template execution error:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			return
		}

		if usernameSanitized == "user" && passwordSanitized == "pass" {

			permissions := make(map[string]bool)
			permissions["quicksearch"] = true
			permissions["documents"] = true
			permissions["results"] = true

			tokenString, err := createToken(usernameSanitized, permissions)
			if err != nil {
				http.Error(w, "Failed to generate token", http.StatusInternalServerError)
				return
			}

			// Set the token as a cookie
			expirationTime := time.Now().Add(5 * time.Minute)
			http.SetCookie(w, &http.Cookie{
				Name:     "token",
				Value:    tokenString,
				Expires:  expirationTime,
				HttpOnly: true, // Important for security
			})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return

		} else {
			//fmt.Fprintf(w, "Login failed")

			token, err := generateCSRFToken()
			if err != nil {
				fmt.Println("CSRF token generation error:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			fmt.Println("created CSRF token: ", token)
			setCSRFCookie(w, token)

			tmpl, err := template.ParseFiles("templates/login.html")
			if err != nil {
				fmt.Println("template parsing error:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			err = tmpl.Execute(w, LoginPageData{
				Username: usernameSanitized,
				Password: passwordSanitized,
				Error:    "login invalid",
				Token:    token,
			})
			if err != nil {
				fmt.Println("template execution error:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			return
		}
	}

	//tmpl := template.Must(template.ParseFiles("login.html"))
	//tmpl.Execute(w, nil)

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {

	fmt.Println("in handleDashboard()")

	claims, err := verifyToken(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusUnauthorized)
		return
	}

	token, err := generateCSRFToken()
	if err != nil {
		fmt.Println("CSRF token generation error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	fmt.Println("created CSRF token: ", token)
	setCSRFCookie(w, token)

	data := PageData{
		LoggedIn:      true,
		Username:      claims.Username,
		Token:         token,
		Navigation:    getNavigation(false),
		RecentGophers: []string{"1", "2", "3"}, // Simulated results
		Documents:     []string{},
		LabResults:    []string{},
	}

	err = tmpl.ExecuteTemplate(w, "base.html", data)
	if err != nil {
		fmt.Println("template execution error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func handleDocuments(w http.ResponseWriter, r *http.Request) {

	fmt.Println("in handleDocuments()")

	claims, err := verifyToken(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusUnauthorized)
		return
	}

	v, ok := claims.Permissions["documents"]
	if ok != true {
		fmt.Println("error accessing claim permissions")
		http.Redirect(w, r, "/", http.StatusUnauthorized)
		return
	}

	if v != true {
		fmt.Println("claim permission is not true")
		http.Redirect(w, r, "/", http.StatusUnauthorized)
		return
	}

	token, err := generateCSRFToken()
	if err != nil {
		fmt.Println("CSRF token generation error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	fmt.Println("created CSRF token: ", token)
	setCSRFCookie(w, token)

	gopherDemographics, err := getGopherDemographics(claims.GopherId)
	if err != nil {
		fmt.Println("get gopher demographics error:", err)
		http.Error(w, "get gopher demographics error", http.StatusInternalServerError)
		return
	}
	
	data := PageData{
		LoggedIn:      true,
		Username:      claims.Username,
		Token:         token,
		Navigation:    getNavigation(true),
		GopherDemographics:    gopherDemographics,
		RecentGophers: []string{},
		Documents:     []string{"Document 1", "Document 2", "Document 3"},
		LabResults:    []string{},
	}

	err = tmpl.ExecuteTemplate(w, "base.html", data)
	if err != nil {
		fmt.Println("template execution error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func handleResults(w http.ResponseWriter, r *http.Request) {

	fmt.Println("in handleResults()")

	claims, err := verifyToken(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusUnauthorized)
		return
	}

	v, ok := claims.Permissions["results"]
	if ok != true {
		fmt.Println("error accessing claim permissions")
		http.Redirect(w, r, "/", http.StatusUnauthorized)
		return
	}

	if v != true {
		fmt.Println("claim permission is not true")
		http.Redirect(w, r, "/", http.StatusUnauthorized)
		return
	}

	token, err := generateCSRFToken()
	if err != nil {
		fmt.Println("CSRF token generation error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	fmt.Println("created CSRF token: ", token)
	setCSRFCookie(w, token)

	gopherDemographics, err := getGopherDemographics(claims.GopherId)
	if err != nil {
		fmt.Println("get gopher demographics error:", err)
		http.Error(w, "get gopher demographics error", http.StatusInternalServerError)
		return
	}
	
	data := PageData{
		LoggedIn:      true,
		Username:      claims.Username,
		Token:         token,
		Navigation:    getNavigation(true),
		GopherDemographics: gopherDemographics,
		RecentGophers: []string{},
		Documents:     []string{},
		LabResults:    []string{"Lab Result 1", "Lab Result 2", "Lab Result 3"},
	}

	err = tmpl.ExecuteTemplate(w, "base.html", data)
	if err != nil {
		fmt.Println("template execution error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func handleSearch(w http.ResponseWriter, r *http.Request) {

	fmt.Println("in handleSearch()")

	if r.Method == http.MethodPost {

		claims, err := verifyToken(r)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusUnauthorized)
			return
		}

		v, ok := claims.Permissions["quicksearch"]
		if ok != true {
			fmt.Println("error accessing claim permissions")
			http.Redirect(w, r, "/", http.StatusUnauthorized)
			return
		}

		if v != true {
			fmt.Println("claim permission is not true")
			http.Redirect(w, r, "/", http.StatusUnauthorized)
			return
		}

		err = r.ParseForm()
		if err != nil {
			fmt.Println("error parsing form:", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		query := r.FormValue("query")
		querySanitized := sanitizeUserInput(query)
		gopherId := querySanitized
		
		//searchResults := []string{"Gopher A", "Gopher B", "Gopher C"} // Simulated results
		
		gopherDemographics, err := getGopherDemographics(gopherId)
		if err != nil {
			fmt.Println("get gopher demographics error:", err)
			http.Error(w, "get gopher demographics error", http.StatusInternalServerError)
			return
		}
				
		tokenString, err := createTokenWithGopherId(claims.Username, claims.Permissions, gopherId)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// Set the token as a cookie
		expirationTime := time.Now().Add(5 * time.Minute)
		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    tokenString,
			Expires:  expirationTime,
			HttpOnly: true, // Important for security
		})

		data := PageData{
			LoggedIn:      true,
			Username:      claims.Username,
			Navigation:    getNavigation(true),
			GopherDemographics: gopherDemographics,
			RecentGophers: []string{},
			Documents:     []string{},
			LabResults:    []string{"Lab Result 1", "Lab Result 2", "Lab Result 3"},
		}

		err = tmpl.ExecuteTemplate(w, "base.html", data)
		if err != nil {
			fmt.Println("template execution error:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}
