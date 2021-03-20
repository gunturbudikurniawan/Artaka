package api

import (
	"fmt"
	"log"
	"os"

	"github.com/go-redis/redis/v7"
	"github.com/gunturbudikurniawan/Artaka/api/controllers"
	"github.com/joho/godotenv"
)

var server = controllers.Server{}
var client *redis.Client

func init() {
	// loads values from .env into the system
	if err := godotenv.Load(); err != nil {
		log.Print("sad .env file found")
	}
	//Initializing redis
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}
	client = redis.NewClient(&redis.Options{
		Addr: dsn,
	})
	_, err := client.Ping().Result()
	if err != nil {
		fmt.Print(err)
	}
}

func Run() {

	var err error
	err = godotenv.Load()
	if err != nil {
		log.Fatalf("Error getting env, %v", err)
	} else {
		fmt.Println("We are getting values")
	}

	server.Initialize(os.Getenv("DB_DRIVER"), os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_PORT"), os.Getenv("DB_HOST"), os.Getenv("DB_NAME"))

	apiPort := os.Getenv("PORT")
	fmt.Printf("Listening to port %s", "5000")
	if apiPort == "" {
		apiPort = "5000"
	}
	server.Run(":" + apiPort)
}
