package main

import (
	"os"

	"github.com/vadim8q258475/auth-microservice/app"
	"github.com/vadim8q258475/auth-microservice/service"
	userpb "github.com/vadim8q258475/user-microservice/pb"

	"github.com/go-chi/jwtauth"
	"github.com/joho/godotenv"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}

	godotenv.Load(".env")

	port := os.Getenv("PORT")
	userPort := os.Getenv("USER_PORT")
	host := os.Getenv("HOST")
	authSecretKey := os.Getenv("SECRET_KEY")

	conn, err := grpc.Dial(host+":"+userPort, grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	logger.Info("success connection with port " + userPort)
	defer conn.Close()

	userService := userpb.NewUserServiceClient(conn)

	authToken := jwtauth.New("HS256", []byte(authSecretKey), nil)

	authService := service.NewAuthService(userService, authToken, logger)

	server := grpc.NewServer()

	app := app.NewApp(authService, server, logger, port)

	err = app.Run()
	if err != nil {
		panic(err)
	}
}
