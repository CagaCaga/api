package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"
	"os"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"github.com/joho/godotenv"
)

// Register the author of some actions and logs
type Author struct {
	ID interface{} `bson:"id" json:"id"`
}

// URL shortened information
type URLShortened struct {
	Author       Author      `bson:"author" json:"author"`
	Url          string      `bson:"url" json:"url"`
	Code         interface{} `bson:"code" json:"code"`
	IsVanity     bool        `bson:"is_vanity" json:"is_vanity"`
	VanityURL    interface{} `bson:"vanity_url" json:"vanity_url"`
	CreationDate string      `bson:"created_at" json:"created_at"`
}

// User is the base struct for general users
type User struct {
	Token     string `bson:"token" json:"token"`
	ID        string `bson:"id" json:"id"`
	Name      string `bson:"name" json:"name"`
	Username  string `bson:"username" json:"username"`
	Email     string `bson:"email" json:"email"`
	Password  string `bson:"password" json:"password"`
	Premium   bool   `bson:"premium" json:"premium"`
	CreatedAt string `bson:"created_at" json:"created_at"`
}

// Response to GetMe
type GetMe struct {
	Token string `json:"token"`
}

func main() {
	API(MyMongo(getEnv("MONGO_URI")))
}

/// Return MongoDB Connection
func MyMongo(atlasURI string) *mongo.Client {
	client, err := mongo.NewClient(options.Client().ApplyURI(atlasURI))
	if err != nil {
		panic(err.Error())
	}

	err = client.Connect(context.TODO())
	if err != nil {
		panic(err.Error())
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		panic(err.Error())
	}

	return client
}

// API is the main function to initialize the server and register the routes
func API(client *mongo.Client) {
	server := fiber.New()
	server.Use(cors.New())

	server.Use("/api/v1", func(c *fiber.Ctx) error {
		c.Accepts("application/json")
		return c.Next()
	})

	server.Use(limiter.New(limiter.Config{
		Max:      15,
		Duration: 5000,
		Key: limiter.ConfigDefault.KeyGenerator,
		LimitReached: func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"status":      429,
				"message":     "rate limited",
				"data":        nil,
				"exited_code": 1,
			})
		},
	}))

	RegisterRoutes(server, client)

	server.Listen(":5000")
}

// Register all routes
func RegisterRoutes(server *fiber.App, client *mongo.Client) {
	server.Get("/api/v1", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":      200,
			"message":     "ok",
			"data":        nil,
			"exited_code": 0,
		})
	})

	RegisterUserRoutes(server, client)
	RegisterShortenerRoutes(server, client)
}

// Register routes related to the shortener
func RegisterShortenerRoutes(server *fiber.App, client *mongo.Client) {
	server.Get("/api/v1/get/shortener/:id/data", func(c *fiber.Ctx) error {
		if len(c.Params("id")) < 2 || len(c.Params("id")) > 100 {
			return c.JSON(fiber.Map{
				"status":      200,
				"message":     "invalid shortener code",
				"data":        nil,
				"exited_code": 1,
			})
		}

		shortenerData := make(map[string]interface{})
		err := client.Database("JeanShortener").Collection("urls").FindOne(context.TODO(), bson.D{{"code", c.Params("id")}}).Decode(&shortenerData)
		if shortenerData["_id"] == nil {
			err = client.Database("JeanShortener").Collection("urls").FindOne(context.TODO(), bson.D{{"vanity_url", c.Params("id")}}).Decode(&shortenerData)
			if err != nil {
				if isUnknownDocument(err.Error()) {
					return c.JSON(fiber.Map{
						"status":      500,
						"message":     "non-existent user",
						"data":        nil,
						"exited_code": 1,
					})
				}

				return c.JSON(fiber.Map{
					"status":      200,
					"message":     err.Error(),
					"data":        nil,
					"exited_code": 1,
				})
			}
		}

		return c.JSON(fiber.Map{
			"status":      200,
			"message":     "ok",
			"data":        shortenerData,
			"exited_code": 0,
		})
	})

	server.Post("/api/v1/post/shortener/create", func(c *fiber.Ctx) error {
		body := make(map[string]interface{})
		err := json.Unmarshal([]byte(string(c.Body())), &body)
		if err != nil {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     err.Error(),
				"data":        nil,
				"exited_code": 1,
			})
		}

		if body["url"] == nil || body["is_vanity"] == nil || (body["url"] != nil && body["is_vanity"] != nil && reflect.TypeOf(body["url"]).String() != "string" || reflect.TypeOf(body["is_vanity"]).String() != "bool" || !isValidUrl(body["url"].(string))) {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "invalid body",
				"data":        nil,
				"exited_code": 1,
			})
		}

		if body["vanity_url"] != nil {
			vanityNameRegexp := regexp.MustCompile("^[a-zA-Z0-9_.-]*$")
			if !vanityNameRegexp.MatchString(body["vanity_url"].(string)) {
				return c.JSON(fiber.Map{
					"status":      500,
					"message":     "the vanity url only can be contain letters and numbers",
					"data":        nil,
					"exited_code": 1,
				})
			}

			if len(body["vanity_url"].(string)) > 100 {
				return c.JSON(fiber.Map{
					"status":      500,
					"message":     "the vanity url length can't be higher than 30 characters",
					"data":        nil,
					"exited_code": 1,
				})
			}

			if len(body["vanity_url"].(string)) < 2 {
				return c.JSON(fiber.Map{
					"status":      500,
					"message":     "the vanity url length can't be lower than 2 characters",
					"data":        nil,
					"exited_code": 1,
				})
			}
		}

		idKey, idValue := body["user_id"]
		tokenKey, tokenValue := body["user_token"]

		var user = make(map[string]interface{})
		if (idKey != nil && idValue) && (tokenKey != nil && tokenValue) {
			err = client.Database("JeanShortener").Collection("users").FindOne(context.TODO(), bson.D{{"id", body["user_id"]}}).Decode(&user)
			if err != nil {
				if isUnknownDocument(err.Error()) {
					return c.JSON(fiber.Map{
						"status":      500,
						"message":     "non-existent user",
						"data":        nil,
						"exited_code": 1,
					})
				}

				return c.JSON(fiber.Map{
					"status":      500,
					"message":     err.Error(),
					"data":        nil,
					"exited_code": 1,
				})
			}

			if strings.Compare(body["user_token"].(string), user["token"].(string)) != 0 {
				return c.JSON(fiber.Map{
					"status":      500,
					"message":     "the session you are currently active in has a problem, please delete your localStorage (https://developer.chrome.com/docs/devtools/storage/localstorage/#delete)",
					"data":        nil,
					"exited_code": 1,
				})
			}
		}

		var userID interface{}
		if body["user_id"] != nil && user["id"] != nil {
			userID = body["user_id"].(string)
		}

		var urlData = &URLShortened{}
		if user["premium"] == true && body["is_vanity"] != false && userID != nil {
			var checkVanityURLAvailability = make(map[string]interface{})


			var userVanityURLS []interface{}
			result, err := client.Database("JeanShortener").Collection("urls").Find(context.TODO(), bson.M{"author": bson.M{"id": userID}, "is_vanity": true})
			if err != nil {
				return c.JSON(fiber.Map{
					"status":      500,
					"message":     err.Error(),
					"data":        nil,
					"exited_code": 1,
				})
			}

			result.All(context.TODO(), &userVanityURLS)
			if len(userVanityURLS) > 10 {
				return c.JSON(fiber.Map{
					"status":      500,
					"message":     "you cannot have more than 10 vanity urls at the same time",
					"data":        nil,
					"exited_code": 1,
				})
			}

			err = client.Database("JeanShortener").Collection("urls").FindOne(context.TODO(), bson.D{{"vanity_url", body["vanity_url"].(string)}}).Decode(&checkVanityURLAvailability)
			if checkVanityURLAvailability["_id"] != nil {
				return c.JSON(fiber.Map{
					"status":      500,
					"message":     "vanity url already exist",
					"data":        nil,
					"exited_code": 1,
				})
			}

			urlData = &URLShortened{
				Author: Author{
					ID: userID,
				},
				Url:          body["url"].(string),
				Code:         nil,
				IsVanity:     body["is_vanity"].(bool),
				VanityURL:    body["vanity_url"].(string),
				CreationDate: time.Now().String(),
			}
		} else if user["premium"] == false && body["is_vanity"] != nil && body["is_vanity"] == true {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "vanity url is only available for premium users",
				"data":        nil,
				"exited_code": 1,
			})
		} else {
			urlCode := tokenGenerator(3)
			checkURLCodeAvailability := make(map[string]interface{})
			err = client.Database("JeanShortener").Collection("urls").FindOne(context.TODO(), bson.D{{"code", urlCode}}).Decode(&checkURLCodeAvailability)
			if err != nil {
				if !isUnknownDocument(err.Error()) {
					return c.JSON(fiber.Map{
						"status":      500,
						"message":     err.Error(),
						"data":        nil,
						"exited_code": 1,
					})
				}
			}

			urlData = &URLShortened{
				Author: Author{
					ID: userID,
				},
				Url:          body["url"].(string),
				Code:         urlCode,
				IsVanity:     false,
				VanityURL:    nil,
				CreationDate: time.Now().String(),
			}
		}

		_, err = client.Database("JeanShortener").Collection("urls").InsertOne(context.TODO(), urlData)
		if err != nil {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     err.Error(),
				"data":        nil,
				"exited_code": 1,
			})
		}

		return c.JSON(fiber.Map{
			"status":      200,
			"message":     "ok",
			"data":        urlData,
			"exited_code": 0,
		})
	})

	server.Delete("/api/v1/post/shortener/:id/delete", func(c *fiber.Ctx) error {
		body := make(map[string]interface{})
		err := json.Unmarshal([]byte(string(c.Body())), &body)
		if err != nil {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     err.Error(),
				"data":        nil,
				"exited_code": 1,
			})
		}

		if len(c.Params("id")) < 2 || len(c.Params("id")) > 100 {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "invalid shortener code",
				"data":        nil,
				"exited_code": 1,
			})
		}
		if body["user_id"] == nil || reflect.TypeOf(body["user_id"]).String() != "string" {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "invalid body",
				"data":        nil,
				"exited_code": 1,
			})
		}

		user := make(map[string]interface{})
		err = client.Database("JeanShortener").Collection("users").FindOne(context.TODO(), bson.D{{"id", body["user_id"]}}).Decode(&user)
		if err != nil {
			if(isUnknownDocument(err.Error())) {
				return c.JSON(fiber.Map{
					"status":      500,
					"message":     "non-existent user",
					"data":        nil,
					"exited_code": 1,
				})
			}

			return c.JSON(fiber.Map{
				"status":      500,
				"message":     err.Error(),
				"data":        nil,
				"exited_code": 1,
			})
		}

		if user["id"] == nil {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "non-existent user",
				"data":        nil,
				"exited_code": 1,
			})
		}

		if user["token"] != body["token"] {
			return c.JSON(fiber.Map{
				"status":      401,
				"message":     "unauthorized",
				"data":        nil,
				"exited_code": 1,
			})
		}

		result, err := client.Database("JeanShortener").Collection("urls").DeleteOne(context.TODO(), bson.M{"author": bson.M{"id": body["user_id"]}, "code": c.Params("id")})

		if result.DeletedCount != 1 {
			result, err = client.Database("JeanShortener").Collection("urls").DeleteOne(context.TODO(), bson.M{"author": bson.M{"id": body["user_id"]}, "vanity_url": c.Params("id")})
		}

		if err != nil {
			if isUnknownDocument(err.Error()) {
				return c.JSON(fiber.Map{
					"status":      200,
					"message":     "not-existent url shorted",
					"data":        nil,
					"exited_code": 1,
				})
			}

			if err != nil {
				return c.JSON(fiber.Map{
					"status":      200,
					"message":     err.Error(),
					"data":        nil,
					"exited_code": 1,
				})
			}
		}

		return c.JSON(fiber.Map{
			"status":      200,
			"message":     "deleted",
			"data":        result,
			"exited_code": 0,
		})
	})
}

// Register routes related to users and authentication
func RegisterUserRoutes(server *fiber.App, client *mongo.Client) {
	server.Get("/api/v1/get/public/user/:id", func(c *fiber.Ctx) error {
		data := make(map[string]interface{})
		err := client.Database("JeanShortener").Collection("users").FindOne(context.TODO(), bson.D{{"id", c.Params("id")}}).Decode(&data)
		if err != nil {
			if isUnknownDocument(err.Error()) {
				return c.JSON(fiber.Map{
					"status":      500,
					"message":     "non-existent user",
					"data":        nil,
					"exited_code": 1,
				})
			}

			return c.JSON(fiber.Map{
				"status":      500,
				"message":     err.Error(),
				"data":        nil,
				"exited_code": 1,
			})
		}

		data["email"] = nil
		data["password"] = nil
		data["token"] = nil

		return c.JSON(fiber.Map{
			"status":      200,
			"message":     "authorized",
			"data":        data,
			"exited_code": 0,
		})
	})

	server.Post("/api/v1/post/all/user/:id", func(c *fiber.Ctx) error {
		body := make(map[string]interface{})
		err := json.Unmarshal([]byte(string(c.Body())), &body)
		if err != nil {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     err.Error(),
				"data":        nil,
				"exited_code": 1,
			})
		}

		if body["token"] == nil || reflect.TypeOf(body["token"]).String() != "string" {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "invalid body",
				"data":        nil,
				"exited_code": 1,
			})
		}

		var data = make(map[string]interface{})
		err = client.Database("JeanShortener").Collection("users").FindOne(context.TODO(), bson.D{{"id", c.Params("id")}}).Decode(&data)
		if err != nil {
			if isUnknownDocument(err.Error()) {
				return c.JSON(fiber.Map{
					"status":      500,
					"message":     "non-existent user",
					"data":        nil,
					"exited_code": 1,
				})
			}

			return c.JSON(fiber.Map{
				"status":      500,
				"message":     err.Error(),
				"data":        nil,
				"exited_code": 1,
			})
		}

		if data["token"] == nil {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "user data has issues",
				"data":        nil,
				"exited_code": 1,
			})
		}

		if strings.Compare(data["token"].(string), body["token"].(string)) != 0 {
			return c.JSON(fiber.Map{
				"status":      401,
				"message":     "unauthorized",
				"data":        nil,
				"exited_code": 1,
			})
		}

		return c.JSON(fiber.Map{
			"status":      200,
			"message":     "authorized",
			"data":        data,
			"exited_code": 0,
		})
	})

	server.Post("/api/v1/post/user/data/dashboard/:id", func(c *fiber.Ctx) error {
		body := make(map[string]interface{})
		err := json.Unmarshal([]byte(string(c.Body())), &body)
		if err != nil {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     err.Error(),
				"data":        nil,
				"exited_code": 1,
			})
		}

		if body["token"] == nil || reflect.TypeOf(body["token"]).String() != "string" {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "invalid body",
				"data":        nil,
				"exited_code": 1,
			})
		}

		var data = make(map[string]interface{})
		err = client.Database("JeanShortener").Collection("users").FindOne(context.TODO(), bson.D{{"id", c.Params("id")}}).Decode(&data)
		if err != nil {
			if isUnknownDocument(err.Error()) {
				return c.JSON(fiber.Map{
					"status":      500,
					"message":     "non-existent user",
					"data":        nil,
					"exited_code": 1,
				})
			}

			return c.JSON(fiber.Map{
				"status":      500,
				"message":     err.Error(),
				"data":        nil,
				"exited_code": 1,
			})
		}

		if data["token"] == nil {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "user data has issues",
				"data":        nil,
				"exited_code": 1,
			})
		}

		if strings.Compare(data["token"].(string), body["token"].(string)) != 0 {
			return c.JSON(fiber.Map{
				"status":      401,
				"message":     "unauthorized",
				"data":        nil,
				"exited_code": 1,
			})
		}

		var urls []interface{}
		urlsFound, err := client.Database("JeanShortener").Collection("urls").Find(context.TODO(), bson.M{"author": bson.M{"id": c.Params("id")}})
		if err != nil {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     err.Error(),
				"data":        nil,
				"exited_code": 1,
			})
		}

		defer urlsFound.Close(context.TODO())

		for urlsFound.Next(context.TODO()) {
			var urlObject bson.M
			if err = urlsFound.Decode(&urlObject); err != nil {
				panic(err)
			}

			urls = append(urls, urlObject)
		}

		data["urls"] = urls

		return c.JSON(fiber.Map{
			"status":      200,
			"message":     "authorized",
			"data":        data,
			"exited_code": 0,
		})
	})

	server.Post("/api/v1/post/user/create", func(c *fiber.Ctx) error {
		body := make(map[string]interface{})
		err := json.Unmarshal([]byte(string(c.Body())), &body)
		if err != nil {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     err.Error(),
				"data":        nil,
				"exited_code": 1,
			})
		}

		if body["name"] == nil ||
			body["username"] == nil ||
			body["email"] == nil ||
			body["password"] == nil ||
			body["confirm_password"] == nil {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "invalid body",
				"data":        nil,
				"exited_code": 1,
			})
		}

		if reflect.TypeOf(body["name"]).String() != "string" ||
			reflect.TypeOf(body["username"]).String() != "string" ||
			reflect.TypeOf(body["email"]).String() != "string" ||
			reflect.TypeOf(body["password"]).String() != "string" ||
			reflect.TypeOf(body["confirm_password"]).String() != "string" {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "invalid body",
				"data":        nil,
				"exited_code": 1,
			})
		}

		if len(body["username"].(string)) >= 25 || len(body["username"].(string)) <= 3 {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "the length of the username must be higher than 3 and less than 25",
				"data":        nil,
				"exited_code": 1,
			})
		}

		userData := make(map[string]interface{})
		err = client.Database("JeanShortener").Collection("users").FindOne(context.TODO(), bson.D{{"username", body["username"]}}).Decode(&userData)
		if err != nil {
			if !isUnknownDocument(err.Error()) {
				return c.JSON(fiber.Map{
					"status":      500,
					"message":     err.Error(),
					"data":        nil,
					"exited_code": 1,
				})
			}
		}

		if userData["username"] != nil {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "already exist an user with that username",
				"data":        nil,
				"exited_code": 0,
			})
		}

		if len(body["name"].(string)) >= 100 || len(body["name"].(string)) <= 1 {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "the length of the name must be higher than 1 and less than 100",
				"data":        nil,
				"exited_code": 1,
			})
		}

		var usernameRegexp = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
		if !usernameRegexp.MatchString(body["username"].(string)) {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "not valid username",
				"data":        nil,
				"exited_code": 1,
			})
		}

		var emailRegexp = regexp.MustCompile(`^(([^<>()[\]\.,;:\s@\"]+(\.[^<>()[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^<>()[\]\.,;:\s@\"]+\.)+[^<>()[\]\.,;:\s@\"]{2,})$`)
		if !emailRegexp.MatchString(body["email"].(string)) {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "not valid email",
				"data":        nil,
				"exited_code": 1,
			})
		}

		err = client.Database("JeanShortener").Collection("users").FindOne(context.TODO(), bson.D{{"email", body["email"]}}).Decode(&userData)
		if err != nil {
			if !isUnknownDocument(err.Error()) {
				return c.JSON(fiber.Map{
					"status":      500,
					"message":     "existing user with that username",
					"data":        nil,
					"exited_code": 1,
				})
			}
		}
		if userData["username"] != nil {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "existing user with that email",
				"data":        nil,
				"exited_code": 1,
			})
		}

		if len(body["password"].(string)) <= 8 || len(body["password"].(string)) >= 1500 {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "the length of the password must be higher than 8 and less than 1500",
				"data":        nil,
				"exited_code": 1,
			})
		}

		if strings.Compare(body["password"].(string), body["confirm_password"].(string)) != 0 {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "the password doesn't match with confirm password",
				"data":        nil,
				"exited_code": 1,
			})
		}

		token := tokenGenerator(100)
		id := tokenGenerator(20)
		user := User{
			Token:     token,
			ID:        id,
			Name:      body["name"].(string),
			Username:  body["username"].(string),
			Email:     body["email"].(string),
			Password:  body["password"].(string),
			Premium:   false,
			CreatedAt: time.Now().String(),
		}

		_, err = client.Database("JeanShortener").Collection("users").InsertOne(context.TODO(), user)
		if err != nil {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     err.Error(),
				"data":        nil,
				"exited_code": 1,
			})
		}

		return c.JSON(fiber.Map{
			"status":  200,
			"message": "created",
			"data": fiber.Map{
				"token": token,
				"id":    id,
			},
			"exited_code": 0,
		})
	})

	server.Post("/api/v1/post/user/request/credentials", func(c *fiber.Ctx) error {
		body := make(map[string]interface{})
		err := json.Unmarshal([]byte(string(c.Body())), &body)
		if err != nil {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     err.Error(),
				"data":        nil,
				"exited_code": 1,
			})
		}

		if body["username_email"] == nil ||
			body["password"] == nil ||
			reflect.TypeOf(body["username_email"]).String() != "string" || reflect.TypeOf(body["password"]).String() != "string" {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "invalid body",
				"data":        nil,
				"exited_code": 1,
			})
		}

		user := make(map[string]interface{})
		err = client.Database("JeanShortener").Collection("users").FindOne(context.TODO(), bson.D{{"username", body["username_email"]}}).Decode(&user)
		if err != nil {
			err = client.Database("JeanShortener").Collection("users").FindOne(context.TODO(), bson.D{{"email", body["username_email"]}}).Decode(&user)
			if err != nil {
				if isUnknownDocument(err.Error()) {
					return c.JSON(fiber.Map{
						"status":      500,
						"message":     "doesn't exist none user with this username or email",
						"data":        nil,
						"exited_code": 1,
					})
				}

				return c.JSON(fiber.Map{
					"status":      500,
					"message":     err.Error(),
					"data":        nil,
					"exited_code": 1,
				})
			}
		}

		if user["id"] == nil || user["token"] == nil || user["username"] == nil || user["email"] == nil || user["password"] == nil {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "your account have issues, please contact to support",
				"data":        nil,
				"exited_code": 1,
			})
		}

		if strings.Compare(user["password"].(string), string(body["password"].(string))) != 0 {
			return c.JSON(fiber.Map{
				"status":      500,
				"message":     "your password not match",
				"data":        nil,
				"exited_code": 1,
			})
		}

		return c.JSON(fiber.Map{
			"status":  200,
			"message": "authorized",
			"data": fiber.Map{
				"id":    user["id"].(string),
				"token": user["token"].(string),
			},
			"exited_code": 0,
		})
	})
}

// Generate token for User Token and User ID
func tokenGenerator(count int) string {
	b := make([]byte, count)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Check if an error returned by mongo client is about not found document
func isUnknownDocument(err string) bool {
	if strings.Compare(err, "mongo: no documents in result") == 0 {
		return true
	} else {
		return false
	}
}

// Check if string is URL
func isValidUrl(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false
	}

	u, err := url.Parse(toTest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}

func getEnv(key string) string {
	err := godotenv.Load(".env")
  
	if err != nil {
	 	panic("Error loading .env file")
	}
  
	return os.Getenv(key)
}
