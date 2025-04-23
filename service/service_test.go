package service

import (
	"context"
	"testing"

	"github.com/go-chi/jwtauth"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vadim8q258475/auth-microservice/mock"
	pb "github.com/vadim8q258475/auth-microservice/pb"
	userpb "github.com/vadim8q258475/user-microservice/pb"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthService_GenerateToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock.NewMockUserServicer(ctrl)
	authToken := jwtauth.New("HS256", []byte("authSecretKey"), nil)
	logger := zap.NewNop()

	service := NewAuthService(mockUserService, authToken, logger)

	token, err := service.GenerateToken("email")

	assert.NoError(t, err)

	_, trueToken, _ := authToken.Encode(map[string]interface{}{"email": "email"})

	assert.Equal(t, token, trueToken)

}

func TestAuthService_IsUserExists(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock.NewMockUserServicer(ctrl)
	authToken := jwtauth.New("HS256", []byte("authSecretKey"), nil)
	logger := zap.NewNop()

	service := NewAuthService(mockUserService, authToken, logger)

	list := userpb.ListResponse{Users: []*userpb.User{
		{Email: "email1"},
		{Email: "email2"},
	}}

	mockUserService.EXPECT().List(gomock.Any(), gomock.Any()).Return(&list, nil).Times(2)

	result, err := service.IsUserExists(context.Background(), "email1")

	assert.NoError(t, err)
	assert.Equal(t, result, list.Users[0])

	result, err = service.IsUserExists(context.Background(), "email123")

	assert.NoError(t, err)
	assert.Nil(t, result)

	mockUserService.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, assert.AnError).Times(1)

	_, err = service.IsUserExists(context.Background(), "email123")

	assert.Error(t, err)
}

func TestAuthService_IsTokenValid(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock.NewMockUserServicer(ctrl)
	authToken := jwtauth.New("HS256", []byte("authSecretKey"), nil)
	logger := zap.NewNop()

	service := NewAuthService(mockUserService, authToken, logger)
	_, token, _ := authToken.Encode(map[string]interface{}{"email": "email1"})

	user := userpb.User{Email: "email1"}
	mockUserService.EXPECT().GetByEmail(gomock.Any(), gomock.Any()).Return(&user, nil)

	request := pb.TokenRequest{Token: token}
	response, err := service.IsTokenValid(context.Background(), &request)

	assert.NoError(t, err)
	assert.Equal(t, response.TokenMessage, "valid token")
	assert.Equal(t, response.Valid, true)

	request.Token = ""
	_, err = service.IsTokenValid(context.Background(), &request)

	assert.Error(t, err)

	request.Token = "emailerr"
	_, err = service.IsTokenValid(context.Background(), &request)

	assert.Error(t, err)
}

func TestAuthService_Login(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock.NewMockUserServicer(ctrl)
	authToken := jwtauth.New("HS256", []byte("authSecretKey"), nil)
	logger := zap.NewNop()

	service := NewAuthService(mockUserService, authToken, logger)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("pass1"), bcrypt.DefaultCost)
	hashedPassword2, _ := bcrypt.GenerateFromPassword([]byte("pass2"), bcrypt.DefaultCost)
	list := userpb.ListResponse{Users: []*userpb.User{
		{Email: "email1", Password: string(hashedPassword)},
		{Email: "email2", Password: string(hashedPassword2)},
	}}

	// ошибка поиска
	mockUserService.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, assert.AnError)

	request := pb.LoginRequest{Email: "email3", Password: "pass1"}
	_, err := service.Login(context.Background(), &request)

	assert.Error(t, err)
	// пользователь не найден
	mockUserService.EXPECT().List(gomock.Any(), gomock.Any()).Return(&list, nil)

	request = pb.LoginRequest{Email: "email3", Password: "pass1"}
	_, err = service.Login(context.Background(), &request)

	assert.Error(t, err)
	// ok
	mockUserService.EXPECT().List(gomock.Any(), gomock.Any()).Return(&list, nil)

	request = pb.LoginRequest{Email: "email1", Password: "pass1"}
	response, err := service.Login(context.Background(), &request)

	assert.NoError(t, err)
	assert.NotEqual(t, response.Token, "")
}

func TestAuthService_Register(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserService := mock.NewMockUserServicer(ctrl)
	logger := zap.NewNop()
	authToken := jwtauth.New("HS256", []byte("authSecretKey"), nil)
	service := NewAuthService(mockUserService, authToken, logger)

	// ошибка во время поиска юзера
	mockUserService.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, assert.AnError)
	request := &pb.ReqisterRequest{Email: "email1"}
	_, err := service.Register(context.Background(), request)
	assert.Error(t, err)
	// пользователь уже есть
	users := &userpb.ListResponse{Users: []*userpb.User{
		{Email: "email1"},
		{Email: "email2"},
	}}
	mockUserService.EXPECT().List(gomock.Any(), gomock.Any()).Return(users, nil).Times(3)
	_, err = service.Register(context.Background(), request)
	assert.Error(t, err)
	// ошибка создания пользователя
	reqisterReq := pb.ReqisterRequest{Email: "email3", Password: "pass3"}
	mockUserService.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, assert.AnError)
	_, err = service.Register(context.Background(), &reqisterReq)
	assert.Error(t, err)
	// все ок
	createResponse := userpb.CreateResponse{Query: "ok"}

	mockUserService.EXPECT().Create(gomock.Any(), gomock.Any()).Return(&createResponse, nil)
	response, err := service.Register(context.Background(), &reqisterReq)
	assert.NoError(t, err)
	assert.Equal(t, "ok", response.RegisterMessage)
}
