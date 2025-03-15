package main

import (
        "fmt"
        "html/template"
        "net/http"
)

type Navigation struct {
	Page	string
	Endpoint	string
}

type PageData struct {
        LoggedIn        bool
        Username        string
        Navigation   []Navigation
        SearchResults   []string
        PatientName     string
        RecentPatients  []string
        Documents      []string
        LabResults      []string
}

func main() {
        http.HandleFunc("/", handleLogin)
        http.HandleFunc("/dashboard", handleDashboard)
        http.HandleFunc("/documents", handleDocuments)
        http.HandleFunc("/results", handleResults)
        http.HandleFunc("/search", handleSearch)
        fmt.Println("Server listening on :8080")
        http.ListenAndServe(":8080", nil)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodPost {
                username := r.FormValue("username")
                password := r.FormValue("password")

                if username == "user" && password == "pass" {
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
        data := PageData{
                LoggedIn:       true,
                Username:       "user",
                Navigation:    getNavigation(false),
                RecentPatients:	[]string{"Patient A", "Patient B", "Patient C"}, // Simulated results
                Documents: []string{},
                LabResults:    []string{},
        }
        tmpl, err := template.ParseFiles("dashboard.html", "base.html", "nav.html", "banner.html", "system_name.html", "quick_search.html", "logout.html", "patient_banner.html", "recent_patients.html", "documents.html", "lab_results.html")
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
        data := PageData{
                LoggedIn:       true,
                Username:       "user",
                Navigation:    getNavigation(true),
                PatientName:   "placeholder",
                RecentPatients: []string{},
                Documents:    []string{"Document 1", "Document 2", "Document 3"},
                LabResults: []string{},
        }
        tmpl, err := template.ParseFiles("dashboard.html", "base.html", "nav.html", "banner.html", "system_name.html", "quick_search.html", "logout.html", "patient_banner.html", "recent_patients.html", "documents.html", "lab_results.html")
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
        data := PageData{
                LoggedIn:       true,
                Username:       "user",
                Navigation:    getNavigation(true),
                PatientName:   "placeholder",
                RecentPatients: []string{},
                Documents: []string{},
                LabResults:    []string{"Lab Result 1", "Lab Result 2", "Lab Result 3"},
        }
        tmpl, err := template.ParseFiles("dashboard.html", "base.html", "nav.html", "banner.html", "system_name.html", "quick_search.html", "logout.html", "patient_banner.html", "recent_patients.html", "documents.html", "lab_results.html")
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
        if r.Method == http.MethodPost {
                query := r.FormValue("query")
                //searchResults := []string{"Patient A", "Patient B", "Patient C"} // Simulated results
                data := PageData{
                        LoggedIn:      true,
                        Username:      "user",
                        Navigation:    getNavigation(true),
                        PatientName:   query,
                        RecentPatients:    []string{},
                        Documents:    []string{},
                        LabResults:    []string{"Lab Result 1", "Lab Result 2", "Lab Result 3"},
                }
                tmpl, err := template.ParseFiles("dashboard.html", "base.html", "nav.html", "banner.html", "system_name.html", "quick_search.html", "logout.html", "patient_banner.html", "recent_patients.html", "documents.html", "lab_results.html")
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

