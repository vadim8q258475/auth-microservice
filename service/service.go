package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	pb "github.com/vadim8q258475/auth-microservice/pb"
	userpb "github.com/vadim8q258475/user-microservice/pb"
	"google.golang.org/grpc"

	"github.com/go-chi/jwtauth"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

const rpcTimeoutMS = 400 * time.Millisecond

type UserServicer interface {
	GetByEmail(context.Context, *userpb.GetReuqest, ...grpc.CallOption) (*userpb.User, error)
	Create(context.Context, *userpb.CreateRequest, ...grpc.CallOption) (*userpb.CreateResponse, error)
	List(context.Context, *userpb.ListRequest, ...grpc.CallOption) (*userpb.ListResponse, error)
}

type AuthService struct {
	pb.UnimplementedAuthServiceServer
	userService UserServicer
	authToken   *jwtauth.JWTAuth
	logger      *zap.Logger
}

func NewAuthService(userService UserServicer, authToken *jwtauth.JWTAuth, logger *zap.Logger) *AuthService {
	return &AuthService{
		userService: userService,
		authToken:   authToken,
		logger:      logger,
	}
}

func (s *AuthService) GenerateToken(email string) (string, error) {
	_, token, err := s.authToken.Encode(map[string]interface{}{"email": email})
	return token, err
}

func (s *AuthService) IsUserExists(ctx context.Context, email string) (*userpb.User, error) {
	listCtx, cancel := context.WithTimeout(ctx, rpcTimeoutMS)
	defer cancel()
	users, err := s.userService.List(listCtx, &userpb.ListRequest{})
	if err != nil {
		s.logger.Error(fmt.Sprintf("failed to get users; error: %s", err.Error()))
		return nil, err
	}
	for _, user := range users.Users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, nil
}

func (s *AuthService) IsTokenValid(ctx context.Context, request *pb.TokenRequest) (*pb.TokenResponse, error) {
	tokenString := request.Token
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	token, err := s.authToken.Decode(tokenString)
	if err != nil {
		s.logger.Error(fmt.Sprintf("token parsing failed: %w", err))
		return nil, fmt.Errorf("token parsing failed: %w", err)
	}

	if token == nil {
		s.logger.Error("empty token")
		return nil, errors.New("empty token")
	}

	claims, err := token.AsMap(ctx)
	if err != nil {
		s.logger.Error(fmt.Sprintf("invalid token claims: %w", err))
		return nil, fmt.Errorf("invalid token claims: %w", err)
	}

	email, ok := claims["email"].(string)
	if !ok || email == "" {
		s.logger.Error(fmt.Sprintf("email claim not found or invalid: %w", err))
		return nil, errors.New("email claim not found or invalid")
	}

	getCtx, cancel := context.WithTimeout(ctx, rpcTimeoutMS)
	defer cancel()

	user, err := s.userService.GetByEmail(getCtx, &userpb.GetReuqest{Email: email})
	if err != nil {
		s.logger.Error(fmt.Sprintf("get by email error: %w", err))
		return nil, err
	}

	response := &pb.TokenResponse{
		Valid:        true,
		UserId:       user.Id,
		TokenMessage: "valid token",
	}
	s.logger.Info("token valid")
	return response, nil
}

func (s *AuthService) Login(ctx context.Context, request *pb.LoginRequest) (*pb.LoginResponse, error) {
	user, err := s.IsUserExists(ctx, request.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		s.logger.Info(fmt.Sprintf("cant login. user is not exists"))
		return &pb.LoginResponse{Token: ""}, errors.New("user is not exists")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password))
	if err != nil {
		s.logger.Error(fmt.Sprintf("compare hash and password error: %s", err.Error()))
		return nil, err
	}

	token, err := s.GenerateToken(request.Email)
	if err != nil {
		s.logger.Error(fmt.Sprintf("gen token error: %s", err.Error()))
		return nil, err
	}
	s.logger.Info(fmt.Sprintf("login user %s successfuly", request.Email))
	return &pb.LoginResponse{Token: token}, nil
}
func (s *AuthService) Register(ctx context.Context, request *pb.ReqisterRequest) (*pb.ReqisterResponse, error) {
	user, err := s.IsUserExists(ctx, request.Email)
	if err != nil {
		return nil, err
	}
	if user != nil {
		s.logger.Info(fmt.Sprintf("cant register. user is already exists"))
		return nil, errors.New("user already exists")
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error(fmt.Sprintf("hash error: %s", err.Error()))
		return nil, errors.New("hash error")
	}
	createRequest := &userpb.CreateRequest{Email: request.Email, Password: string(hashedPassword)}
	response, err := s.userService.Create(ctx, createRequest)
	if err != nil {
		s.logger.Error(fmt.Sprintf("create error: %s", err.Error()))
		return nil, err
	}
	s.logger.Info(fmt.Sprintf(response.Query))
	return &pb.ReqisterResponse{RegisterMessage: response.Query}, nil
}
