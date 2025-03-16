package main

import (
	"crypto/rand"
	"encoding/base64"
        "fmt"
        "html/template"
        "net/http"
        "time"
        
        "github.com/golang-jwt/jwt/v5"
)

//var jwtKey = []byte("your-secret-key")
var jwtKey = []byte{}

type Claims struct {
	Username string `json:"Username"`
	jwt.RegisteredClaims
}

type Navigation struct {
	Page	string
	Endpoint	string
}

type PageData struct {
        LoggedIn        bool
        Username        string
        Navigation   []Navigation
        SearchResults   []string
        GopherName     string
        RecentGophers  []string
        Documents      []string
        LabResults      []string
}

func main() {

	secret, err := generateRandomSecret(32) // 32 bytes = 256 bits
	if err != nil {
		fmt.Println("Error generating secret:", err)
		return
	}
	fmt.Println("Generated Secret Key:", secret)
	jwtKey = []byte(secret)
	
        http.HandleFunc("/", handleLogin)
        http.HandleFunc("/dashboard", handleDashboard)
        http.HandleFunc("/documents", handleDocuments)
        http.HandleFunc("/results", handleResults)
        http.HandleFunc("/search", handleSearch)
        fmt.Println("Server listening on :8080")
        http.ListenAndServe(":8080", nil)
}

func generateRandomSecret(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	
	return base64.URLEncoding.EncodeToString(bytes), nil
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

func handleLogin(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodPost {
                username := r.FormValue("username")
                password := r.FormValue("password")

                if username == "user" && password == "pass" {
                	// Create JWT claims
                	expirationTime := time.Now().Add(5 * time.Minute)
                	claims := &Claims{
                		Username: username,
                		RegisteredClaims: jwt.RegisteredClaims{
                			ExpiresAt: jwt.NewNumericDate(expirationTime),
                		},
                	}
                	// Create the JWT token
                	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
                	tokenString, err := token.SignedString(jwtKey)
                	if err != nil {
                		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
                		return
                	}
                	// Set the token as a cookie
                	http.SetCookie(w, &http.Cookie{
                		Name: "token",
                		Value: tokenString,
                		Expires: expirationTime,
                		HttpOnly: true, // Important for security
                	})
                        http.Redirect(w, r, "/dashboard", http.StatusFound)
                        return
                } else {
                        fmt.Fprintf(w, "Login failed")
                        return
                }
        }

        tmpl := template.Must(template.ParseFiles("login.html"))
        tmpl.Execute(w, nil)
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

func handleDashboard(w http.ResponseWriter, r *http.Request) {
        
        claims, err := verifyToken(r)
        if err != nil {
        	http.Redirect(w, r, "/", http.StatusUnauthorized)
        	return
        }
        
        data := PageData{
                LoggedIn:       true,
                Username:       claims.Username,
                Navigation:    getNavigation(false),
                RecentGophers:	[]string{"Gopher A", "Gopher B", "Gopher C"}, // Simulated results
                Documents: []string{},
                LabResults:    []string{},
        }
        tmpl, err := template.ParseFiles("dashboard.html", "base.html", "nav.html", "banner.html", "system_name.html", "quick_search.html", "logout.html", "gopher_banner.html", "recent_gophers.html", "documents.html", "lab_results.html")
        if err != nil {
        	fmt.Println("template parsing error:", err)
        	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        	return
        }
        err = tmpl.ExecuteTemplate(w, "base.html", data)
        if err != nil {
        	fmt.Println("template execution error:", err)
        	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        	return
        }
}

func handleDocuments(w http.ResponseWriter, r *http.Request) {
        
        claims, err := verifyToken(r)
        if err != nil {
        	http.Redirect(w, r, "/", http.StatusUnauthorized)
        	return
        }
        
        data := PageData{
                LoggedIn:       true,
                Username:       claims.Username,
                Navigation:    getNavigation(true),
                GopherName:   "placeholder",
                RecentGophers: []string{},
                Documents:    []string{"Document 1", "Document 2", "Document 3"},
                LabResults: []string{},
        }
        tmpl, err := template.ParseFiles("dashboard.html", "base.html", "nav.html", "banner.html", "system_name.html", "quick_search.html", "logout.html", "gopher_banner.html", "recent_gophers.html", "documents.html", "lab_results.html")
        if err != nil {
        	fmt.Println("template parsing error:", err)
        	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        	return
        }
        err = tmpl.ExecuteTemplate(w, "base.html", data)
        if err != nil {
        	fmt.Println("template execution error:", err)
        	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        	return
        }
}

func handleResults(w http.ResponseWriter, r *http.Request) {
        
        claims, err := verifyToken(r)
        if err != nil {
        	http.Redirect(w, r, "/", http.StatusUnauthorized)
        	return
        }
        
        data := PageData{
                LoggedIn:       true,
                Username:       claims.Username,
                Navigation:    getNavigation(true),
                GopherName:   "placeholder",
                RecentGophers: []string{},
                Documents: []string{},
                LabResults:    []string{"Lab Result 1", "Lab Result 2", "Lab Result 3"},
        }
        tmpl, err := template.ParseFiles("dashboard.html", "base.html", "nav.html", "banner.html", "system_name.html", "quick_search.html", "logout.html", "gopher_banner.html", "recent_gophers.html", "documents.html", "lab_results.html")
        if err != nil {
        	fmt.Println("template parsing error:", err)
        	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        	return
        }
        err = tmpl.ExecuteTemplate(w, "base.html", data)
        if err != nil {
        	fmt.Println("template execution error:", err)
        	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        	return
        }
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
        
        claims, err := verifyToken(r)
        if err != nil {
        	http.Redirect(w, r, "/", http.StatusUnauthorized)
        	return
        }
        
        if r.Method == http.MethodPost {
                query := r.FormValue("query")
                //searchResults := []string{"Gopher A", "Gopher B", "Gopher C"} // Simulated results
                data := PageData{
                        LoggedIn:      true,
                        Username:       claims.Username,
                        Navigation:    getNavigation(true),
                        GopherName:   query,
                        RecentGophers:    []string{},
                        Documents:    []string{},
                        LabResults:    []string{"Lab Result 1", "Lab Result 2", "Lab Result 3"},
                }
                tmpl, err := template.ParseFiles("dashboard.html", "base.html", "nav.html", "banner.html", "system_name.html", "quick_search.html", "logout.html", "gopher_banner.html", "recent_gophers.html", "documents.html", "lab_results.html")
        	if err != nil {
       		 	fmt.Println("template parsing error:", err)
        		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        		return
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

