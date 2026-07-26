package helpers

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
    "github.com/imshawan/gin-backend-starter/models"
    "go.mongodb.org/mongo-driver/bson/primitive"
)

type Claims struct {
    ID       primitive.ObjectID `bson:"_id,omitempty"`
    Username string `json:"username"`
    jwt.RegisteredClaims
}

func SignJWTToken(user models.User) (string, error) {
	jwtSecret := viper.GetString("JWT_SECRET")
    expiryHours := viper.GetInt("JWT_EXPIRY_HOURS")

    // Define JWT claims
    claims := Claims{
        ID: user.ID,
        Username: user.Username,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expiryHours) * time.Hour)), // Set token expiration time
            IssuedAt:  jwt.NewNumericDate(time.Now()), // Set token issued time
            // Include other claims as needed
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
        // Ensure that the signing method is what you expect
        if token.Method != jwt.SigningMethodHS256 {
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

    // Validate the token claims
    if claims, ok := token.Claims.(*Claims); ok && token.Valid {
        return claims, nil
    } else {
        return nil, errors.New("invalid token")
    }
}