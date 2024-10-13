package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var tmpl = template.Must(template.ParseGlob("templates/*.html"))

const contractAddress string = "0x23742f1FdC91483cC42D1fccD67C74b9f2D2588b"
const ABIFilePath string = "../build/contracts/PetShop.json"

var ContractABI string = ""

type User struct {
	UserID          int    `json:"user_id"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	MetaMaskAccount string `json:"metamask_account"`
	UserType        string `json:"user_type"`
}

var db *sql.DB
var sessionMutex sync.Mutex

// In-memory session store
var sessions = map[string]string{}

// Initialize database
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create table if it doesn't exist
	sqlStmt := `
	CREATE TABLE IF NOT EXISTS users (
		user_id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		metamask_account TEXT,
		user_type TEXT NOT NULL
	);
	`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}
}

// Generate a random session token
func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func setSession(w http.ResponseWriter, username, userType string) error {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	// Generate session token
	sessionToken, err := generateSessionToken()
	if err != nil {
		return err
	}

	// Store the session token, username, and userType
	sessions[sessionToken] = username + "|" + userType // Store as "username|userType"

	// Set the cookie with the session token
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   false, // Change to true if using HTTPS
		Path:     "/",
	})
	return nil
}

// Get the username and userType from the session token
func getSessionUser(r *http.Request) (string, string, error) {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	// Get the session token from the cookie
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return "", "", err
	}

	// Retrieve the stored data
	data, exists := sessions[cookie.Value]
	if !exists {
		return "", "", fmt.Errorf("invalid session")
	}

	// Split the username and userType
	parts := strings.Split(data, "|")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid session data")
	}

	return parts[0], parts[1], nil // Return username and userType
}

// Delete a session (for logout)
func deleteSession(w http.ResponseWriter, r *http.Request) {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	// Get the session token from the cookie
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return
	}

	// Delete the session
	delete(sessions, cookie.Value)

	// Invalidate the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
		Path:     "/",
	})
}

func main() {
	initDB()
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", landingHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/welcome", welcomeHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/save-metamask-account", saveMetaMaskAccountHandler)
	http.HandleFunc("/list-pet", listPetHandler)
	http.HandleFunc("/view-pets", viewPetHandler)
	http.HandleFunc("/list-product", listProductHandler)
	http.HandleFunc("/view-products", viewProductHandler)
	http.HandleFunc("/order-history", viewOrderHistoryHandler)

	fmt.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func landingHandler(w http.ResponseWriter, r *http.Request) {
	tmpl.ExecuteTemplate(w, "landing.html", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Render the login form with no error
		tmpl.ExecuteTemplate(w, "login.html", nil)
	} else if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		var userType, storedPassword, metamaskAccount string
		err := db.QueryRow("SELECT password, metamask_account, user_type FROM users WHERE username=?", username).Scan(&storedPassword, &metamaskAccount, &userType)

		if err == sql.ErrNoRows || storedPassword != password {
			data := struct {
				ErrorMessage string
			}{
				ErrorMessage: "Invalid username or password",
			}
			tmpl.ExecuteTemplate(w, "login.html", data)
			return
		} else if err != nil {
			slog.Error("db error", err.Error())
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		err = setSession(w, username, userType)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		data := struct {
			Username        string
			MetaMaskAccount string
			UserType        string
		}{
			Username:        username,
			MetaMaskAccount: metamaskAccount,
			UserType:        userType,
		}
		http.Redirect(w, r, "/welcome", http.StatusSeeOther)
		tmpl.ExecuteTemplate(w, "welcome.html", data)
	}
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl.ExecuteTemplate(w, "signup.html", nil)
	} else if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		userType := r.FormValue("user_type")

		var exists bool
		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username=?)", username).Scan(&exists)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		if exists {
			data := struct {
				ErrorMessage string
			}{
				ErrorMessage: "User already exists",
			}
			tmpl.ExecuteTemplate(w, "signup.html", data)
		} else {
			// Insert the new user into the database
			_, err = db.Exec("INSERT INTO users (username, password, user_type, metamask_account) VALUES (?, ?, ?, ?)", username, password, userType, "")
			if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}
	}
}

func welcomeHandler(w http.ResponseWriter, r *http.Request) {
	// Get the username from the session
	username, usertype, err := getSessionUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if ContractABI == "" {
		abiFile, err := os.Open("../build/contracts/PetShop.json")
		if err != nil {
			http.Error(w, "Unable to load ABI", http.StatusInternalServerError)
			return
		}
		defer abiFile.Close()

		abiBytes, _ := io.ReadAll(abiFile)
		ContractABI = string(abiBytes)
	}
	var metaMaskAccount string
	err = db.QueryRow("SELECT metamask_account FROM users WHERE username = ?", username).
		Scan(&metaMaskAccount)
	if err != nil {
		slog.Error("error in getting user", "error", err.Error())
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	data := struct {
		Username        string
		UserType        string
		WalletAddress   string
		ContractABI     string
		ContractAddress string
	}{
		Username:        username,
		UserType:        usertype,
		WalletAddress:   metaMaskAccount,
		ContractABI:     ContractABI,
		ContractAddress: contractAddress,
	}

	tmpl.ExecuteTemplate(w, "welcome.html", data)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Delete the session (logout)
	deleteSession(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func saveMetaMaskAccountHandler(w http.ResponseWriter, r *http.Request) {
	username, _, err := getSessionUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Decode the MetaMask account from the request body
	var req struct {
		MetaMaskAccount string `json:"metamask_account"`
	}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.MetaMaskAccount == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("UPDATE users SET metamask_account = ? WHERE username = ?", req.MetaMaskAccount, username)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func listPetHandler(w http.ResponseWriter, r *http.Request) {
	username, _, err := getSessionUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	abiFile, err := os.Open("../build/contracts/PetShop.json")
	if err != nil {
		http.Error(w, "Unable to load ABI", http.StatusInternalServerError)
		return
	}
	defer abiFile.Close()

	abiBytes, _ := io.ReadAll(abiFile)
	contractABI := string(abiBytes)

	data := struct {
		ContractABI     string
		ContractAddress string
		Username        string
	}{
		ContractABI:     contractABI,
		ContractAddress: contractAddress,
		Username:        username,
	}
	if err := tmpl.ExecuteTemplate(w, "list-pet.html", data); err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
	}
}

func viewPetHandler(w http.ResponseWriter, r *http.Request) {
	username, userType, err := getSessionUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	var metaMaskAccount string
	err = db.QueryRow("SELECT metamask_account FROM users WHERE username = ?", username).
		Scan(&metaMaskAccount)
	if err != nil {
		slog.Error("error in getting user", "error", err.Error())
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	abiFile, err := os.Open("../build/contracts/PetShop.json")
	if err != nil {
		http.Error(w, "Unable to load ABI", http.StatusInternalServerError)
		return
	}
	defer abiFile.Close()

	abiBytes, _ := io.ReadAll(abiFile)
	contractABI := string(abiBytes)

	data := struct {
		ContractABI     string
		ContractAddress string
		Username        string
		UserType        string
		WalletAddress   string
	}{
		ContractABI:     contractABI,
		ContractAddress: contractAddress,
		Username:        username,
		UserType:        userType,
		WalletAddress:   metaMaskAccount,
	}
	if err := tmpl.ExecuteTemplate(w, "view-pets.html", data); err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
	}
}

func listProductHandler(w http.ResponseWriter, r *http.Request) {
	username, _, err := getSessionUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	abiFile, err := os.Open("../build/contracts/PetShop.json")
	if err != nil {
		http.Error(w, "Unable to load ABI", http.StatusInternalServerError)
		return
	}
	defer abiFile.Close()

	abiBytes, _ := io.ReadAll(abiFile)
	contractABI := string(abiBytes)

	data := struct {
		ContractABI     string
		ContractAddress string
		Username        string
	}{
		ContractABI:     contractABI,
		ContractAddress: contractAddress,
		Username:        username,
	}
	if err := tmpl.ExecuteTemplate(w, "list-product.html", data); err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
	}
}

func viewProductHandler(w http.ResponseWriter, r *http.Request) {
	username, userType, err := getSessionUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	var metaMaskAccount string
	err = db.QueryRow("SELECT metamask_account FROM users WHERE username = ?", username).
		Scan(&metaMaskAccount)
	if err != nil {
		slog.Error("error in getting user", "error", err.Error())
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	abiFile, err := os.Open("../build/contracts/PetShop.json")
	if err != nil {
		http.Error(w, "Unable to load ABI", http.StatusInternalServerError)
		return
	}
	defer abiFile.Close()

	abiBytes, _ := io.ReadAll(abiFile)
	contractABI := string(abiBytes)

	data := struct {
		ContractABI     string
		ContractAddress string
		Username        string
		UserType        string
		WalletAddress   string
	}{
		ContractABI:     contractABI,
		ContractAddress: contractAddress,
		Username:        username,
		UserType:        userType,
		WalletAddress:   metaMaskAccount,
	}
	if err := tmpl.ExecuteTemplate(w, "view-products.html", data); err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
	}
}

func viewOrderHistoryHandler(w http.ResponseWriter, r *http.Request) {
	username, userType, err := getSessionUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	var metaMaskAccount string
	err = db.QueryRow("SELECT metamask_account FROM users WHERE username = ?", username).
		Scan(&metaMaskAccount)
	if err != nil {
		slog.Error("error in getting user", "error", err.Error())
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	abiFile, err := os.Open("../build/contracts/PetShop.json")
	if err != nil {
		http.Error(w, "Unable to load ABI", http.StatusInternalServerError)
		return
	}
	defer abiFile.Close()

	abiBytes, _ := io.ReadAll(abiFile)
	contractABI := string(abiBytes)

	data := struct {
		ContractABI     string
		ContractAddress string
		Username        string
		UserType        string
		WalletAddress   string
	}{
		ContractABI:     contractABI,
		ContractAddress: contractAddress,
		Username:        username,
		UserType:        userType,
		WalletAddress:   metaMaskAccount,
	}
	if err := tmpl.ExecuteTemplate(w, "order-history.html", data); err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
	}
}
