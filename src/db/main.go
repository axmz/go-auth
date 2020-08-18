package db

import (
	"go-auth/src/models"
)

// Sessions sessions db
var Sessions = map[string]string{}

// Users users db
var Users = map[string]models.User{}
