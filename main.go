package main

import (
	"html/template"
	"net/http"

	"go-auth/src/db"
	"go-auth/src/models"
	"go-auth/src/util"

	"golang.org/x/crypto/bcrypt"

	uuid "github.com/satori/go.uuid"
)

var (
	tpl *template.Template
)

type tplData struct {
	Title string
	User  models.User
}

func init() {
	tpl = template.Must(template.ParseGlob("src/templates/*"))
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/secret", secret)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/signup", signup)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, r *http.Request) {
	u := util.GetUser(r)
	d := tplData{"Go!", u}
	tpl.ExecuteTemplate(w, "index.gohtml", d)
}

func secret(w http.ResponseWriter, r *http.Request) {
	u := util.GetUser(r)
	if !util.AlreadyLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	d := tplData{"Top Secret", u}
	tpl.ExecuteTemplate(w, "secret.gohtml", d)
}

func signup(w http.ResponseWriter, r *http.Request) {
	if util.AlreadyLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// get form data
	if r.Method == http.MethodPost {
		un := r.FormValue("username")
		p := r.FormValue("password")
		f := r.FormValue("firstname")
		l := r.FormValue("lastname")

		// check if the username is taken
		if _, ok := db.Users[un]; ok {
			http.Error(w, "Username already taken", http.StatusForbidden)
			return
		}

		sID := uuid.NewV4()
		c := &http.Cookie{
			Value: sID.String(),
			Name:  "session",
		}
		http.SetCookie(w, c)
		db.Sessions[c.Value] = un

		bs, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.MinCost)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		u := models.User{
			UserName: un,
			Password: bs,
			First:    f,
			Last:     l,
		}
		db.Users[un] = u

		// redirect
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	d := tplData{"Sign up", models.User{}}
	tpl.ExecuteTemplate(w, "signup.gohtml", d)

}

func login(w http.ResponseWriter, r *http.Request) {
	if util.AlreadyLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// get form data
	if r.Method == http.MethodPost {
		un := r.FormValue("username")
		p := r.FormValue("password")

		// check if user exists
		u, ok := db.Users[un]
		if !ok {
			http.Error(w, "User or password are incorrect", http.StatusForbidden)
			return
		}

		// check user credentials
		err := bcrypt.CompareHashAndPassword(u.Password, []byte(p))
		if err != nil {
			http.Error(w, "User or password are incorrect", http.StatusForbidden)
			return
		}
		// create session
		sID := uuid.NewV4()
		db.Sessions[sID.String()] = un

		// set cookie
		c := &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		http.SetCookie(w, c)

		// redirect
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
	d := tplData{"Log In", models.User{}}
	tpl.ExecuteTemplate(w, "login.gohtml", d)
}

func logout(w http.ResponseWriter, r *http.Request) {
	// if not logged in then go elsewhere
	if !util.AlreadyLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// get session from cookie
	c, _ := r.Cookie("session")

	// remove session from db
	delete(db.Sessions, c.Value)

	// remove cookie
	c = &http.Cookie{
		Value:  "",
		Name:   "session",
		MaxAge: -1,
	}
	http.SetCookie(w, c)

	// redirect
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// func helmet(h http.HandlerFunc, title string) http.HandlerFunc {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		// head := struct{ Title string }{title}
// 		// tpl.ExecuteTemplate(w, "header", head)
// 		h.ServeHTTP(w, r)
// 	})
// }
