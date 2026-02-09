package handler

import (
	"database/sql"
	"net/http"
)

// ARCH-004: Missing abstraction layer — direct SQL in handlers.

var db *sql.DB

// HandleGetUsers has direct database access in the handler layer.
func HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name, email FROM users WHERE active = true")
	if err != nil {
		http.Error(w, "failed", 500)
		return
	}
	defer rows.Close()

	// Process rows directly in handler — no repository pattern.
	for rows.Next() {
		var id int
		var name, email string
		rows.Scan(&id, &name, &email)
	}

	w.Write([]byte("ok"))
}

// HandleDeleteUser executes raw SQL in the controller layer.
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	_, err := db.Exec("DELETE FROM users WHERE id = ?", r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "failed", 500)
		return
	}
	w.Write([]byte("deleted"))
}
