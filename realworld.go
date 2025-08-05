package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/argon2"
)

var (
	errUserNotFound       = fmt.Errorf("user not found")
	errEmailExists        = fmt.Errorf("user with this email is already exists")
	errUsernameExists     = fmt.Errorf("user with this username is already exists")
	errInvalidCredentials = fmt.Errorf("user not found or password is incorrect")
	errUnauthorized       = fmt.Errorf("unauthorized")
	errInternal           = fmt.Errorf("internal server error")
	errNoSession          = fmt.Errorf("session not found")
)

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	Username  string    `json:"username"`
	password  []byte    `json:"-"`
	Bio       string    `json:"bio"`
	Image     string    `json:"image"`
	Following bool
}

type Token struct {
	Payload string
}

type Session struct {
	User *User
}

type Article struct {
	Author         *User     `json:"author"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Body           string    `json:"body"`
	Slug           string    `json:"slug"`
	TagList        []string  `json:"tagList"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
	Favorited      bool      `json:"favorited"`
	FavoritesCount int       `json:"favoritesCount"`
}

type UserStorage interface {
	AddUser(*User) (*User, error)
	UpdateData(*User, *User) (*User, error)
	GetByEmail(string) (*User, error)
	GetById(string) (*User, error)
}

type UserStMem struct {
	Users []*User
}

func NewUserStMem() *UserStMem {
	return &UserStMem{
		Users: make([]*User, 0, 5),
	}
}

type SessionStorage interface {
	AddSession(*User) (*Token, error)
	DeleteSession(*Session) error
	DeleteAllSessions(*User) error
	GetSession(*Token) (*Session, error)
	CheckSession(*Token) bool
}

type SessionStMem struct {
	Sessions map[Token]*Session
}

func NewSessionStMem() *SessionStMem {
	return &SessionStMem{
		Sessions: make(map[Token]*Session),
	}
}

type Tag struct {
	Payload string
}

type Author struct {
	Username string
}

type ArticleStorage interface {
	AddArticle(*Article) (*Article, error)
	GetAll() ([]*Article, error)
	GetByAuthor(*Author) ([]*Article, error)
	GetByTag(*Tag) ([]*Article, error)
	GetWithFilters(*Author, *Tag) ([]*Article, error)
	Count() int
}

type ArticleStMem struct {
	Articles []*Article
}

func NewArticleStMem() *ArticleStMem {
	return &ArticleStMem{
		Articles: make([]*Article, 0, 5),
	}
}

type ArticleHandler struct {
	ArticleStorage
	SessionStorage
}

type UserHandler struct {
	UserStorage
	SessionStorage
}

func GetApp() http.Handler {
	ss := NewSessionStMem()

	uh := UserHandler{
		UserStorage:    NewUserStMem(),
		SessionStorage: ss,
	}

	ah := ArticleHandler{
		ArticleStorage: NewArticleStMem(),
		SessionStorage: ss,
	}

	r := gin.Default()
	r.Use(authMiddleware(ss))

	r.POST("/api/users", uh.RegisterUser)
	r.POST("/api/users/login", uh.LoginUser)
	r.POST("/api/user/logout", uh.LogoutUser)
	r.GET("/api/user", uh.GetUser)
	r.PUT("/api/user", uh.UpdateUser)

	r.POST("/api/articles", ah.AddNewArticle)
	r.GET("/api/articles", ah.GetArticles)

	return r
}

func (uStMem *UserStMem) AddUser(user *User) (*User, error) {
	for _, u := range uStMem.Users {
		if u.Email == user.Email {
			return nil, errEmailExists
		}
		if u.Username == user.Username {
			return nil, errUsernameExists
		}
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	uStMem.Users = append(uStMem.Users, user)
	return user, nil
}

func (uStMem *UserStMem) UpdateData(dst, src *User) (*User, error) {
	valDst := reflect.ValueOf(dst).Elem()
	valSrc := reflect.ValueOf(src).Elem()
	updated := false

	for i := 0; i < valDst.NumField(); i++ {
		typeField := valDst.Type().Field(i)
		if typeField.Name == "password" {
			continue
		}

		valFieldDst := valDst.Field(i)
		valFieldSrc := valSrc.Field(i)

		switch typeField.Type.Kind() {
		case reflect.String:
			if !reflect.DeepEqual(valFieldDst, valFieldSrc) &&
				valFieldSrc.Interface().(string) != "" {
				valFieldDst.SetString(string(valFieldSrc.Interface().(string)))
				if !updated {
					dst.UpdatedAt = time.Now()
					updated = true
				}
			}
		}
	}

	return dst, nil
}

func (uStMem *UserStMem) GetByEmail(email string) (*User, error) {
	for i, user := range uStMem.Users {
		if user.Email == email {
			return uStMem.Users[i], nil
		}
	}

	return nil, errUserNotFound
}

func (uStMem *UserStMem) GetById(ID string) (*User, error) {
	for i, user := range uStMem.Users {
		if user.ID == ID {
			return uStMem.Users[i], nil
		}
	}

	return nil, errUserNotFound
}

func (ss *SessionStMem) AddSession(user *User) (*Token, error) {
	token := &Token{
		Payload: RandStringRunes(tokenLen),
	}

	ss.Sessions[*token] = &Session{User: user}
	return token, nil
}

func (ss *SessionStMem) DeleteSession(sess *Session) error {
	for token, session := range ss.Sessions {
		if session == sess {
			delete(ss.Sessions, token)
		}
	}
	return nil
}

func (ss *SessionStMem) DeleteAllSessions(user *User) error {
	for token, session := range ss.Sessions {
		if session.User == user {
			delete(ss.Sessions, token)
		}
	}
	return nil
}

func (ss *SessionStMem) GetSession(token *Token) (*Session, error) {
	if session, isExists := ss.Sessions[*token]; isExists {
		return session, nil
	}
	return nil, errNoSession
}

func (ss *SessionStMem) CheckSession(token *Token) bool {
	_, isExists := ss.Sessions[*token]
	return isExists
}

func (as *ArticleStMem) AddArticle(article *Article) (*Article, error) {
	article.CreatedAt = time.Now()
	article.UpdatedAt = time.Now()
	as.Articles = append(as.Articles, article)
	return article, nil
}

func (as *ArticleStMem) GetAll() ([]*Article, error) {
	return as.Articles, nil
}

func (as *ArticleStMem) GetByAuthor(author *Author) ([]*Article, error) {
	res := make([]*Article, 0, len(as.Articles))
	for _, article := range as.Articles {
		if article.Author.Username == author.Username {
			res = append(res, article)
		}
	}
	return res, nil
}

func (as *ArticleStMem) GetByTag(tag *Tag) ([]*Article, error) {
	res := make([]*Article, 0, len(as.Articles))
	for _, article := range as.Articles {
		if slices.Contains(article.TagList, tag.Payload) {
			res = append(res, article)
		}
	}
	return res, nil
}

func (as *ArticleStMem) GetWithFilters(author *Author, tag *Tag) ([]*Article, error) {
	if author == nil || author.Username == "" {
		if tag == nil || tag.Payload == "" {
			return as.GetAll()
		}
		return as.GetByTag(tag)
	}
	if tag == nil || tag.Payload == "" {
		return as.GetByAuthor(author)
	}

	res := make([]*Article, 0, len(as.Articles))
	for _, article := range as.Articles {
		if article.Author.Username == author.Username &&
			slices.Contains(article.TagList, tag.Payload) {
			res = append(res, article)
		}
	}
	return res, nil
}

func (as *ArticleStMem) Count() int {
	return len(as.Articles)
}

type regRequest struct {
	User struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
}

type authorizedResponse struct {
	User struct {
		*User
		Token string `json:"token"`
	}
}

const saltLen = 8

func (uh UserHandler) RegisterUser(c *gin.Context) {
	var preReg regRequest
	if err := c.BindJSON(&preReg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": errInternal.Error()})
		return
	}

	// params validation
	salt := RandStringRunes(saltLen)
	pass := hashPassword(preReg.User.Password, salt)

	addedUser, err := uh.AddUser(&User{
		Email:    preReg.User.Email,
		Username: preReg.User.Username,
		password: pass,
	})
	if err != nil {
		if errors.Is(err, errEmailExists) || errors.Is(err, errUsernameExists) {
			c.JSON(http.StatusConflict, gin.H{"message": err.Error()})
			return
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"message": errInternal.Error()})
			return
		}
	}

	token, err := uh.AddSession(addedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": errInternal.Error()})
		return
	}

	resp := authorizedResponse{}
	resp.User.User = addedUser
	resp.User.Token = token.Payload
	c.JSON(http.StatusCreated, resp)
}

func hashPassword(plainPassword, salt string) []byte {
	hashedPass := argon2.IDKey([]byte(plainPassword), []byte(salt), 1, 64*1024, 4, 32)
	res := make([]byte, len(salt))
	copy(res, salt)
	return append(res, hashedPass...)
}

type loginRequest struct {
	User struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
}

const tokenLen = 32

func (uh UserHandler) LoginUser(c *gin.Context) {
	var preLogin loginRequest
	if err := c.BindJSON(&preLogin); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": errInternal.Error()})
		return
	}
	// params validation
	user, err := uh.GetByEmail(preLogin.User.Email)
	if err != nil {
		if errors.Is(err, errUserNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"message": errInvalidCredentials.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"message": errInternal.Error()})
		return
	}

	salt := string(user.password[:saltLen])
	if !bytes.Equal(hashPassword(preLogin.User.Password, salt), user.password) {
		c.JSON(http.StatusUnauthorized, gin.H{"message": errInvalidCredentials.Error()})
		return
	}

	token, err := uh.AddSession(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": errInternal.Error()})
		return
	}

	resp := authorizedResponse{}
	resp.User.User = user
	resp.User.Token = token.Payload
	c.JSON(http.StatusOK, resp)
}

const s string = "session"

var noAuth = map[string]struct{}{
	"POST /api/users":       struct{}{},
	"POST /api/users/login": struct{}{},
	"GET /api/articles":     struct{}{},
}

func authMiddleware(ss SessionStorage) gin.HandlerFunc {
	return func(c *gin.Context) {
		reqStr := c.Request.Method + " " + c.Request.URL.Path
		if _, isExist := noAuth[reqStr]; !isExist {
			authHeader := c.GetHeader("Authorization")
			ts := strings.Split(authHeader, " ")
			if len(ts) != 2 {
				c.JSON(http.StatusUnauthorized, gin.H{"message": errUnauthorized.Error()})
				return
			}
			session, err := ss.GetSession(&Token{Payload: ts[1]})
			if err != nil {
				if errors.Is(err, errNoSession) {
					c.JSON(http.StatusUnauthorized, gin.H{"message": errUnauthorized.Error()})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{"message": errInternal.Error()})
				return
			}
			c.Set(s, session)
		}
		c.Next()
	}
}

func (uh UserHandler) LogoutUser(c *gin.Context) {
	s, exists := c.Get(s)
	session, ok := s.(*Session)
	if !exists || !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"message": errUnauthorized.Error()})
		return
	}
	uh.DeleteSession(session)
}

type getUserResponse struct {
	User *User
}

func (uh UserHandler) GetUser(c *gin.Context) {
	s, exists := c.Get(s)
	session, ok := s.(*Session)
	if !exists || !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"message": errUnauthorized.Error()})
		return
	}

	c.JSON(http.StatusOK, getUserResponse{User: session.User})
}

type updateUserRequest struct {
	User *User
}

func (uh UserHandler) UpdateUser(c *gin.Context) {
	s, exists := c.Get(s)
	session, ok := s.(*Session)
	if !exists || !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"message": errUnauthorized.Error()})
		return
	}

	var preUpdate updateUserRequest
	if err := c.BindJSON(&preUpdate); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": errInternal.Error()})
		return
	}
	// params validation
	updatedUser, err := uh.UpdateData(session.User, preUpdate.User)
	if err != nil {
		if errors.Is(err, errUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"message": errUserNotFound.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"message": errInternal.Error()})
	}

	uh.DeleteAllSessions(updatedUser)
	// errors check
	token, err := uh.AddSession(updatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": errInternal.Error()})
		return
	}

	resp := authorizedResponse{}
	resp.User.User = updatedUser
	resp.User.Token = token.Payload
	c.JSON(http.StatusOK, resp)
}

type AddNewArticleRequest struct {
	Article *Article
}

type ArticleResponse struct {
	Author struct {
		Username string `json:"username"`
		Bio      string `json:"bio"`
	} `json:"author"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Body        string    `json:"body"`
	Slug        string    `json:"slug"`
	TagList     []string  `json:"taglist"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type NewArticleResponse struct {
	Article ArticleResponse
}

func (ah ArticleHandler) AddNewArticle(c *gin.Context) {
	s, exists := c.Get(s)
	session, ok := s.(*Session)
	if !exists || !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"message": errUnauthorized.Error()})
		return
	}

	previewArticle := AddNewArticleRequest{}
	if err := c.BindJSON(&previewArticle); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": errInternal.Error()})
	}
	// params validation
	previewArticle.Article.Author = session.User
	previewArticle.Article.Slug = strings.ReplaceAll(previewArticle.Article.Title, " ", "-")
	newArticle, err := ah.AddArticle(previewArticle.Article)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": errInternal.Error()})
	}

	resp := NewArticleResponse{}
	resp.Article.Author.Username = newArticle.Author.Username
	resp.Article.Author.Bio = newArticle.Author.Bio
	resp.Article.Title = newArticle.Title
	resp.Article.Description = newArticle.Description
	resp.Article.Body = newArticle.Body
	resp.Article.Slug = newArticle.Slug
	resp.Article.TagList = newArticle.TagList
	resp.Article.CreatedAt = newArticle.CreatedAt
	resp.Article.UpdatedAt = newArticle.UpdatedAt
	c.JSON(http.StatusCreated, resp)
}

type getArticlesResponse struct {
	Articles      []*ArticleResponse `json:"articles"`
	ArticlesCount int                `json:"articlesCount"`
}

func (ah ArticleHandler) GetArticles(c *gin.Context) {
	author := c.Query("author")
	tag := c.Query("tag")
	articles, err := ah.GetWithFilters(&Author{Username: author}, &Tag{Payload: tag})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": errInternal.Error()})
		return
	}

	c.JSON(http.StatusOK, getArticlesResponse{
		Articles:      t2T(articles),
		ArticlesCount: len(articles),
	})
}

func t2T(in []*Article) []*ArticleResponse {
	ret := make([]*ArticleResponse, 0, len(in))
	for i := range in {
		ar := ArticleResponse{}
		ar.Title = in[i].Title
		ar.Description = in[i].Description
		ar.Body = in[i].Body
		ar.Slug = in[i].Slug
		ar.TagList = in[i].TagList
		ar.CreatedAt = in[i].CreatedAt
		ar.UpdatedAt = in[i].UpdatedAt
		ar.Author.Username = in[i].Author.Username
		ar.Author.Bio = in[i].Author.Bio
		ret = append(ret, &ar)
	}
	return ret
}
