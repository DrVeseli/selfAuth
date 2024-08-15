package selfauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"time"
)

// User represents a user in the database
type User struct {
	ID       int
	Username string
	Email    string
	Password string
}

// Token represents a token in the database
type Token struct {
	Token     string
	UserID    int
	ExpiresAt time.Time
}

// SignUp registers a new user
func SignUp(username, email, password string) error {
	// TODO: Check if username or email already exists
	// TODO: Hash password
	// TODO: Insert new user into the database
	return nil
}

// LogIn handles the login process by setting a session cookie.
func LogIn(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	// Retrieve the user by email
	user, err := getUserByEmail(email)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verify the password
	if !verifyPassword(user.HashedPassword, password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Define the cookie name and path
	cookieName := "user_token"
	cookiePath := "/"

	// Generate a session token (replace with your actual token generation logic)
	sessionToken, err := generateToken()
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Create a cookie with the session token
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    sessionToken,
		Path:     cookiePath,
		Expires:  time.Now().Add(24 * time.Hour), // Set expiration time (e.g., 24 hours)
		HttpOnly: true,                           // Ensure the cookie is not accessible via JavaScript
		Secure:   true,                           // Ensure the cookie is only sent over HTTPS (recommended for production)
	}

	// Set the cookie in the response
	http.SetCookie(w, cookie)

	// Optionally, you can redirect the user to a protected page
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// GetUserFromToken retrieves a user from a token
func GetUserFromToken(token string) (*User, error) {
	// TODO: Retrieve token from the database
	// TODO: Check if token is expired
	// TODO: Retrieve user from the database by token's user ID
	return nil, nil
}

// LogOut invalidates a token
func LogOut(w http.ResponseWriter, r *http.Request) {
	// Define the cookie name and path
	cookieName := "user_token"
	cookiePath := "/"

	// Create a cookie with the same name and path, but with an expiration time in the past
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     cookiePath,
		Expires:  time.Now().Add(-time.Hour), // Set expiration time in the past
		MaxAge:   -1,                         // Immediately delete the cookie
		HttpOnly: true,                       // Ensure the cookie is not accessible via JavaScript
		Secure:   true,                       // Ensure the cookie is only sent over HTTPS (recommended for production)
	}

	// Set the cookie in the response to delete it
	http.SetCookie(w, cookie)

	// Optionally, you can redirect the user to a login page or another page
	http.Redirect(w, r, "/login", http.StatusSeeOther)

	//TODO : Delete token from the database
}

// Helper function to generate a token
func generateToken() (string, error) {
	buffer := make([]byte, 32)
	_, err := rand.Read(buffer)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(buffer), nil
}

// Helper function to hash a password
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// Helper function to verify a password
func verifyPassword(hashedPassword, password string) bool {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:]) == hashedPassword
}
