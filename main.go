package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// var jwtKey = []byte("your-secret-key")
var jwtKey = []byte{}

/*
type Claims struct {
	Username    string          `json:"Username"`
	Permissions map[string]bool `json:"Permissions"`
	GopherId    string          `json:"GopherId"`
	jwt.RegisteredClaims
}
*/

//type Middleware func(http.HandlerFunc) http.HandlerFunc

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
	LoggedIn           bool
	Username           string
	Token              string
	GopherDemographics GopherDemographics
	Navigation         []Navigation
	SearchResults      []string
	RecentGophers      []string
	Documents          []string
	LabResults         []string
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

	httpServer := &http.Server{Addr: ":8080"}

	// Handle graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-quit
		log.Println("Shutting down server...")
		if err := httpServer.Shutdown(context.Background()); err != nil {
			log.Fatalf("Server forced to shutdown: %v", err)
		}
	}()

	secret, err := generateRandomSecret(32) // 32 bytes = 256 bits
	if err != nil {
		log.Println("Error generating secret:", err)
		return
	}

	log.Println("Generated Secret Key:", secret)
	jwtKey = []byte(secret)

	m := NewGopherMiddleware()

	http.HandleFunc("GET /", handleLogin)
	http.HandleFunc("POST /", m.Chain(handleLogin, m.CSRF()))
	http.HandleFunc("GET /dashboard", m.Chain(handleDashboard, m.JWT()))
	http.HandleFunc("GET /documents", m.Chain(handleDocuments, m.JWT()))
	http.HandleFunc("GET /results", m.Chain(handleResults, m.JWT()))
	http.HandleFunc("POST /search", m.Chain(handleSearch, m.JWT(), m.CSRF()))

	log.Println("Server is running on port 8080...")
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to start server: %v", err)
	}

	log.Println("Server exited cleanly")
}

func handleLogin(w http.ResponseWriter, r *http.Request) {

	log.Println("in handleLogin()")

	if r.Method == http.MethodGet {

		c := NewGopherCSRF()
		token, err := c.GenerateCSRFToken()
		if err != nil {
			log.Println("CSRF token generation error:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		log.Println("GET - created CSRF token: ", token)
		c.SetCSRFCookie(w, token)

		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			log.Println("template parsing error:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		data := LoginPageData{ // Initial empty form
			Token: token,
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			log.Println("template execution error:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		return
	}

	if r.Method == http.MethodPost {

		err := r.ParseForm()
		if err != nil {
			log.Println("error parsing form:", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		s := NewGopherSanitize()
		usernameSanitized := s.SanitizeUserInput(username)
		passwordSanitized := s.SanitizeUserInput(password)

		// Validation logic
		if len(usernameSanitized) < 4 || len(usernameSanitized) > 20 {

			c := NewGopherCSRF()
			token, err := c.GenerateCSRFToken()
			if err != nil {
				log.Println("CSRF token generation error:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			log.Println("created CSRF token: ", token)
			c.SetCSRFCookie(w, token)

			tmpl, err := template.ParseFiles("login.html")
			if err != nil {
				log.Println("template parsing error:", err)
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
				log.Println("template execution error:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			return
		}

		if len(passwordSanitized) < 4 || len(passwordSanitized) > 20 {

			c := NewGopherCSRF()
			token, err := c.GenerateCSRFToken()
			if err != nil {
				log.Println("CSRF token generation error:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			log.Println("created CSRF token: ", token)
			c.SetCSRFCookie(w, token)

			tmpl, err := template.ParseFiles("login.html")
			if err != nil {
				log.Println("template parsing error:", err)
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
				log.Println("template execution error:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			return
		}

		if usernameSanitized == "user" && passwordSanitized == "pass" {

			permissionsArray := []string{"quicksearch", "documents", "results"}
			permissions := strings.Join(permissionsArray, ",")

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

			c := NewGopherCSRF()
			token, err := c.GenerateCSRFToken()
			if err != nil {
				log.Println("CSRF token generation error:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			log.Println("created CSRF token: ", token)
			c.SetCSRFCookie(w, token)

			tmpl, err := template.ParseFiles("templates/login.html")
			if err != nil {
				log.Println("template parsing error:", err)
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
				log.Println("template execution error:", err)
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

	log.Println("in handleDashboard()")

	claims, err := verifyToken(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusUnauthorized)
		return
	}

	c := NewGopherCSRF()
	token, err := c.GenerateCSRFToken()
	if err != nil {
		log.Println("CSRF token generation error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Println("created CSRF token: ", token)
	c.SetCSRFCookie(w, token)

	data := PageData{
		LoggedIn:      true,
		Username:      claims["Username"].(string),
		Token:         token,
		Navigation:    getNavigation(false),
		RecentGophers: []string{"1", "2", "3"}, // Simulated results
		Documents:     []string{},
		LabResults:    []string{},
	}

	err = tmpl.ExecuteTemplate(w, "base.html", data)
	if err != nil {
		log.Println("template execution error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func handleDocuments(w http.ResponseWriter, r *http.Request) {

	log.Println("in handleDocuments()")

	claims, err := verifyToken(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusUnauthorized)
		return
	}

	if !hasPermission("documents", claims["Permissions"].(string)) {
		log.Println("error accessing claim permissions")
		http.Redirect(w, r, "/", http.StatusUnauthorized)
		return
	}

	c := NewGopherCSRF()
	token, err := c.GenerateCSRFToken()
	if err != nil {
		log.Println("CSRF token generation error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Println("created CSRF token: ", token)
	c.SetCSRFCookie(w, token)

	gopherDemographics, err := getGopherDemographics(claims["GopherId"].(string))
	if err != nil {
		log.Println("get gopher demographics error:", err)
		http.Error(w, "get gopher demographics error", http.StatusInternalServerError)
		return
	}

	data := PageData{
		LoggedIn:           true,
		Username:           claims["Username"].(string),
		Token:              token,
		Navigation:         getNavigation(true),
		GopherDemographics: gopherDemographics,
		RecentGophers:      []string{},
		Documents:          []string{"Document 1", "Document 2", "Document 3"},
		LabResults:         []string{},
	}

	err = tmpl.ExecuteTemplate(w, "base.html", data)
	if err != nil {
		log.Println("template execution error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func handleResults(w http.ResponseWriter, r *http.Request) {

	log.Println("in handleResults()")

	claims, err := verifyToken(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusUnauthorized)
		return
	}

	if !hasPermission("results", claims["Permissions"].(string)) {
		log.Println("error accessing claim permissions")
		http.Redirect(w, r, "/", http.StatusUnauthorized)
		return
	}

	c := NewGopherCSRF()
	token, err := c.GenerateCSRFToken()
	if err != nil {
		log.Println("CSRF token generation error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Println("created CSRF token: ", token)
	c.SetCSRFCookie(w, token)

	gopherDemographics, err := getGopherDemographics(claims["GopherId"].(string))
	if err != nil {
		log.Println("get gopher demographics error:", err)
		http.Error(w, "get gopher demographics error", http.StatusInternalServerError)
		return
	}

	data := PageData{
		LoggedIn:           true,
		Username:           claims["Username"].(string),
		Token:              token,
		Navigation:         getNavigation(true),
		GopherDemographics: gopherDemographics,
		RecentGophers:      []string{},
		Documents:          []string{},
		LabResults:         []string{"Lab Result 1", "Lab Result 2", "Lab Result 3"},
	}

	err = tmpl.ExecuteTemplate(w, "base.html", data)
	if err != nil {
		log.Println("template execution error:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func handleSearch(w http.ResponseWriter, r *http.Request) {

	log.Println("in handleSearch()")

	if r.Method == http.MethodPost {

		claims, err := verifyToken(r)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusUnauthorized)
			return
		}

		if !hasPermission("quicksearch", claims["Permissions"].(string)) {
			log.Println("error accessing claim permissions")
			http.Redirect(w, r, "/", http.StatusUnauthorized)
			return
		}

		err = r.ParseForm()
		if err != nil {
			log.Println("error parsing form:", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		query := r.FormValue("query")
		s := NewGopherSanitize()
		querySanitized := s.SanitizeUserInput(query)
		gopherId := querySanitized

		//searchResults := []string{"Gopher A", "Gopher B", "Gopher C"} // Simulated results

		gopherDemographics, err := getGopherDemographics(gopherId)
		if err != nil {
			log.Println("get gopher demographics error:", err)
			http.Error(w, "get gopher demographics error", http.StatusInternalServerError)
			return
		}

		tokenString, err := createTokenWithGopherId(claims["Username"].(string), claims["Permissions"].(string), gopherId)
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
			LoggedIn:           true,
			Username:           claims["Username"].(string),
			Navigation:         getNavigation(true),
			GopherDemographics: gopherDemographics,
			RecentGophers:      []string{},
			Documents:          []string{},
			LabResults:         []string{"Lab Result 1", "Lab Result 2", "Lab Result 3"},
		}

		err = tmpl.ExecuteTemplate(w, "base.html", data)
		if err != nil {
			log.Println("template execution error:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusFound)
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
	switch gopherId {
	case "1":
		return GopherDemographics{
			GopherId:    "1",
			Name:        "Gopher A",
			DateOfBirth: time.Date(1999, 1, 2, 0, 0, 0, 0, time.Local),
		}, nil
	case "2":
		return GopherDemographics{
			GopherId:    "2",
			Name:        "Gopher B",
			DateOfBirth: time.Date(2000, 2, 3, 0, 0, 0, 0, time.Local),
		}, nil
	case "3":
		return GopherDemographics{
			GopherId:    "3",
			Name:        "Gopher C",
			DateOfBirth: time.Date(2001, 3, 4, 0, 0, 0, 0, time.Local),
		}, nil
	default:
		//return GopherDemographics{}, nil
		return GopherDemographics{}, errors.New("gopherId not found")
	}
}

func hasPermission(permission string, permissions string) bool {
	permissionsArray := strings.Split(permissions, ",")
	for _, p := range permissionsArray {
		if p == permission {
			return true
		}
	}
	return false
}

func generateRandomSecret(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

func createToken(username string, permissions string) (string, error) {

	// Create JWT claims
	/*
		expirationTime := time.Now().Add(5 * time.Minute)
		claims := &Claims{
			Username:    username,
			Permissions: permissions,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expirationTime),
			},
		}
	*/

	claims := GopherJWTClaims{
		"sub":         "1234567890",
		"Username":    username,
		"Permissions": permissions,
		"iat":         time.Now().Unix(),
		"exp":         time.Now().Add(5 * time.Minute).Unix(), // expiration claim
	}

	// Create the JWT token
	/*
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			log.Println("error signing JWT")
			//http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return "", err
		}
	*/

	j := NewGopherJWT()
	tokenString, err := j.CreateToken(claims, string(jwtKey[:]))
	if err != nil {
		log.Println("error creating JWT")
		return "", err
	}

	return tokenString, nil
}

func createTokenWithGopherId(username string, permissions string, gopherId string) (string, error) {

	// Create JWT claims
	/*
		expirationTime := time.Now().Add(5 * time.Minute)
		claims := &Claims{
			Username:    username,
			Permissions: permissions,
			GopherId:    gopherId,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expirationTime),
			},
		}
	*/

	claims := GopherJWTClaims{
		"sub":         "1234567890",
		"Username":    username,
		"Permissions": permissions,
		"GopherId":    gopherId,
		"iat":         time.Now().Unix(),
		"exp":         time.Now().Add(5 * time.Minute).Unix(), // expiration claim
	}

	// Create the JWT token
	/*
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			log.Println("error signing JWT")
			//http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return "", err
		}
	*/

	j := NewGopherJWT()
	tokenString, err := j.CreateToken(claims, string(jwtKey[:]))
	if err != nil {
		log.Println("error creating JWT")
		return "", err
	}

	return tokenString, nil
}

func verifyToken(r *http.Request) (GopherJWTClaims, error) {

	cookie, err := r.Cookie("token")
	if err != nil {
		return nil, err
	}

	tokenString := cookie.Value

	/*
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			return nil, err
		}

		if !token.Valid {
			//return nil, fmt.Errorf("invalid token")
			return nil, errors.New("invalid token")
		}
	*/

	j := NewGopherJWT()
	claims, err := j.GetClaims(tokenString)
	if err != nil {
		return nil, fmt.Errorf("Error getting claims: %+v", err)
	}

	return claims, nil
}
