    // Parse the token
    token, err := jwt.ParseWithClaims(signedToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        // Ensure that the signing method is what you expect
        if token == nil || token.Method == nil {
            return nil, errors.New("unexpected signing method")
        }
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            errorMsg := fmt.Sprintf("unexpected signing method: %v", token.Header["alg"])
            return nil, errors.New(errorMsg)
        }
        return []byte(jwtSecret), nil
    })