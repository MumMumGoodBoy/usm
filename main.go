package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/mummumgoodboy/usm/internal/model"
	"github.com/mummumgoodboy/usm/internal/route"
	"github.com/mummumgoodboy/usm/internal/service"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file", err)
	}

	postgresURI := os.Getenv("POSTGRES_URI")
	if postgresURI == "" {
		log.Fatal("POSTGRES_URI is not set")
	}

	db, err := gorm.Open(postgres.Open(postgresURI), &gorm.Config{})
	if err != nil {
		log.Fatal("Error connecting to database", err)
	}

	// Migrate the schema
	db.AutoMigrate(&model.User{})

	log.Println("Database migrated")
	userService, err := service.NewUserService(db, os.Getenv("JWT_KEY"))
	if err != nil {
		log.Fatal("Error creating user service", err)
	}

	route.CreateUserRoute(userService)

	// start the server
	log.Println("Server started at :8080")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}
