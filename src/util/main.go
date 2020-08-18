package util

import (
	"net/http"

	"go-auth/src/db"
	"go-auth/src/models"
)

// GetUser gets the user data
func GetUser(r *http.Request) models.User {
	var u models.User

	c, err := r.Cookie("session")
	if err != nil {
		return u
	}

	if un, ok := db.Sessions[c.Value]; ok {
		u = db.Users[un]
	}

	return u
}

// AlreadyLoggedIn checks if the user is logged in
func AlreadyLoggedIn(r *http.Request) bool {
	c, err := r.Cookie("session")
	if err != nil {
		return false
	}
	_, ok := db.Sessions[c.Value]
	return ok
}
