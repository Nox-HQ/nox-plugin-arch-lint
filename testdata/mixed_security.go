package mixed

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"net/http"
)

// ARCH-003: Security-critical crypto code mixed with business logic and HTTP routes.

// VerifySignature validates an HMAC signature (security-critical).
func VerifySignature(message, signature []byte, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expected := mac.Sum(nil)
	return hmac.Equal(expected, signature)
}

// AuthenticateUser validates credentials (security-critical).
func AuthenticateUser(username, password string) bool {
	// Auth logic here.
	return username != "" && password != ""
}

// HandleCreateOrder is business logic mixed in the same file.
func handleCreateOrder(w http.ResponseWriter, r *http.Request) {
	// Business logic in same file as crypto/auth.
	w.Write([]byte("order created"))
}

// processPayment is business logic that should be in a separate module.
func processPayment(db *sql.DB, amount float64) error {
	_, err := db.Exec("INSERT INTO payments (amount) VALUES (?)", amount)
	return err
}

func init() {
	http.HandleFunc("/orders", handleCreateOrder)
}
