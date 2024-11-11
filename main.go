package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/mummumgoodboy/usm/internal/model"
	"github.com/mummumgoodboy/usm/internal/route"
	"github.com/mummumgoodboy/usm/internal/service"
	"github.com/mummumgoodboy/verify"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file", err)
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

	privateKey := os.Getenv("JWT_PRIVATE_KEY")
	publicKey := os.Getenv("JWT_PUBLIC_KEY")
	port := os.Getenv("PORT")

	log.Println("Database migrated")
	userService, err := service.NewUserService(db, privateKey)
	if err != nil {
		log.Fatal("Error creating user service", err)
	}

	verifier, err := verify.NewJWTVerifier(publicKey)
	if err != nil {
		log.Fatal("Error creating verifier", err)
	}

	route.CreateUserRoute(userService)
	route.MeRoute(userService, verifier)

	// start the server
	err = http.ListenAndServe(":"+port, nil)

	log.Println("Auth server started on port", port)
	if err != nil {
		log.Fatal(err)
	}
}
