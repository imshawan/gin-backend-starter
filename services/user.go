package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/imshawan/gin-backend-starter/helpers"
	"github.com/imshawan/gin-backend-starter/infra/database"
	"github.com/imshawan/gin-backend-starter/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func UserProfile(ctx *gin.Context) {
	user, _ := ctx.Get("User")

	helpers.FormatAPIResponse(ctx, http.StatusOK, user)
}

func RegisterUser(ctx *gin.Context) {
	var userReq models.UserRequest

	// Bind and validate the request body
	if err := ctx.ShouldBind(&userReq); err != nil {
		helpers.FormatAPIResponse(ctx, http.StatusBadRequest, err)
		return
	}

	usersCollection := database.Mongo.Collection("users")

	var existingUser models.User
	if err := usersCollection.FindOne(context.TODO(), bson.M{"email": userReq.Email}).Decode(&existingUser); err != nil && err.Error() != "not found" {
		helpers.FormatAPIResponse(ctx, http.StatusConflict, errors.New("user with this email already exists"))
		return
	}

	if err := usersCollection.FindOne(context.TODO(), bson.M{"username": userReq.Username}).Decode(&existingUser); err == nil {
		helpers.FormatAPIResponse(ctx, http.StatusConflict, errors.New("user with this username already exists"))
		return
	}

	// Hash the password
	hashedPassword, err := helpers.HashPassword(userReq.Password)
	if err != nil {
		helpers.FormatAPIResponse(ctx, http.StatusConflict, err)
		return
	}

	newUser := models.User{
		ID:           primitive.NewObjectID(),
		Username:     userReq.Username,
		Email:        userReq.Email,
		PasswordHash: hashedPassword, // Store the hashed password
		Fullname:     userReq.Fullname,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		IsActive:     true,
	}

	_, err = usersCollection.InsertOne(context.TODO(), newUser)
	if err != nil {
		fmt.Print(err)
		helpers.FormatAPIResponse(ctx, http.StatusInternalServerError, errors.New("failed to register user"))
		return
	}

	helpers.FormatAPIResponse(ctx, http.StatusCreated, gin.H{"message": "User registered successfully"})
}
