package helpers

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
)

// Claims defines the structure for JWT claims
type Claims struct {
	UserID string `json:"user_id"` 
	Email  string `json:"email"` 
	Role   string `json:"role"` 
	jwt.RegisteredClaims
}

// GenerateJWTToken creates a new JWT token for a user
func GenerateJWTToken(userID, email, role string) (string, error) {
	jwtSecret := viper.GetString("JWT_SECRET")

	claims := &Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Create a new token object
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	signedToken, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// ValidateJWTToken parses and validates a JWT token
func ValidateJWTToken(signedToken string) (*Claims, error) {
	jwtSecret := viper.GetString("JWT_SECRET")

	// Parse the token
	token, err := jwt.ParseWithClaims(signedToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure that the token and signing method are not nil
		if token == nil || token.Method == nil {
			return nil, errors.New("unexpected signing method")
		}
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			errorMsg := fmt.Sprintf("unexpected signing method: %v", token.Header["alg"])
			return nil, errors.New(errorMsg)
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenMalformed):
			return nil, errors.New("that's not even a token")
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, errors.New("invalid signature")
		case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, errors.New("token expired or not active yet")
		default:
			return nil, err
		}
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}
