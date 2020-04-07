package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"example.com/hello/models"
	"github.com/BurntSushi/toml"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/volatiletech/sqlboiler/boil"
	"github.com/volatiletech/sqlboiler/queries/qm"
	"golang.org/x/crypto/bcrypt"
)

// Config used to map parameters from toml file
type Config struct {
	Mysql   mysql
	Service service
}

type mysql struct {
	Dbname string
	Host   string
	User   string
	Pass   string
}

type service struct {
	Port      string
	JwtSecret string `toml:"jwt_secret"`
}

type registerForms struct {
	Phone string `json:"phone"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

type authForms struct {
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type checkForms struct {
	Token string `json:"token"`
}

type registerResult struct {
	Password string `json:"password"`
	Message  string `json:"message"`
}

// MyCustomClaims to support user specified key
type MyCustomClaims struct {
	Phone     int64  `json:"phone"`
	Role      string `json:"role"`
	Name      string `json:"name"`
	Timestamp int64  `json:"timestamp"`
	jwt.StandardClaims
}

var conf Config

func main() {
	if _, err := toml.DecodeFile("./config.toml", &conf); err != nil {
		fmt.Println(err)
	}

	fmt.Println(conf)

	// Enter password and generate a salted Hash
	router := gin.Default()
	router.POST("/register", registerHandler)
	router.POST("/login", loginHandler)
	router.POST("/check_token", checkTokenHandler)
	router.Run(conf.Service.Port)
}

func checkTokenHandler(req *gin.Context) {
	var input checkForms
	if err := req.ShouldBindJSON(&input); err != nil {
		req.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	tokenString := input.Token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		hmacSampleSecret := []byte(conf.Service.JwtSecret)
		return hmacSampleSecret, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println("Hasil", claims)
		req.JSON(http.StatusOK, claims)
		return
	}
	req.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
	return
}

func loginHandler(req *gin.Context) {
	var input authForms
	if err := req.ShouldBindJSON(&input); err != nil {
		req.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	password := input.Password
	fmt.Println(password)
	phone := sanitizePhone(input.Phone)
	db, err := connectDB()
	if err != nil {
		fmt.Println(errors.New(err.Error()))
		req.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	ctx := context.Background()

	defer db.Close()
	users, err := models.Users(qm.Where("phone = ?", phone)).One(ctx, db)
	if err != nil {
		req.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	// Process validasi password
	isValid := checkPasswords(users.Password, password)
	isAdmin := users.IsAdmin
	role := "user"
	if isAdmin == 1 {
		role = "admin"
	}

	fmt.Println(isValid)
	if isValid == true {
		// Generate jwt
		secret := []byte(conf.Service.JwtSecret)
		claims := MyCustomClaims{
			users.Phone,
			role,
			users.Name,
			time.Now().Unix(),
			jwt.StandardClaims{},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		// Sign and get the complete encoded token as a string using the secret
		tokenString, err := token.SignedString(secret)

		fmt.Println(tokenString, err)

	} else {
		req.JSON(http.StatusBadRequest, gin.H{"message": "Phone number and password did not match"})
	}

	return
}

func checkPasswords(passwordHash string, password string) bool {
	byteHash := []byte(passwordHash)
	bytePass := []byte(password)
	err := bcrypt.CompareHashAndPassword(byteHash, bytePass)
	if err != nil {
		log.Println(err)
		return false
	}
	return true
}

func registerHandler(req *gin.Context) {
	var input registerForms
	if err := req.ShouldBindJSON(&input); err != nil {
		req.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	// generate 4 letters random password for user, save as encrypted
	password := getPwd(4)
	hash := hashAndSalt(password)

	isAdmin := 0
	if input.Role == "admin" {
		isAdmin = 1
	}

	// Sanitize phone number
	phone := sanitizePhone(input.Phone)

	userObject := &models.User{
		Phone:    phone,
		Password: hash,
		Name:     input.Name,
		IsAdmin:  isAdmin,
	}
	if err := writeDB(userObject); err != nil {
		req.JSON(
			http.StatusConflict,
			gin.H{"message": err.Error()},
		)
	} else {
		req.JSON(http.StatusOK,
			&registerResult{
				Password: string(password),
				Message:  "This is your login password, please keep it safe",
			},
		)
	}
	return
}

func sanitizePhone(phone string) int64 {
	numbers := make([]string, len(phone))
	for _, char := range phone {
		if _, err := strconv.Atoi(string(char)); err == nil {
			numbers = append(numbers, string(char))
		}
	}

	phoneNum, err := strconv.ParseInt(strings.Join(numbers, ""), 10, 64)
	if err != nil {
		return 0
	}
	return phoneNum
}

func connectDB() (*sql.DB, error) {
	dbConfig := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s",
		conf.Mysql.User, conf.Mysql.Pass, conf.Mysql.Host, conf.Mysql.Dbname)
	db, err := sql.Open("mysql", dbConfig)
	if err != nil {
		fmt.Println(err)
		exception := errors.New("Error connect to database")
		return nil, exception
	}

	return db, nil
}

func writeDB(userObject *models.User) error {
	db, err := connectDB()
	if err != nil {
		return errors.New(err.Error())
	}

	ctx := context.Background()
	defer db.Close()
	if err := userObject.Insert(ctx, db, boil.Infer()); err != nil {
		fmt.Println(err)
		exception := errors.New(err.Error())
		return exception
	}
	return nil
}

// Generate 4 letters random password
func getPwd(length int) []byte {
	rand.Seed(time.Now().UnixNano())
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789!@#$%&()"

	// use byte to be hashed using bcrypt
	buf := make([]byte, length)

	for i := 0; i < length; i++ {
		buf[i] = chars[rand.Intn(len(chars))]
	}

	return buf
}

func hashAndSalt(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}

	return string(hash)
}
