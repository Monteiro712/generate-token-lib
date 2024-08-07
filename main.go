package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type authorizationService struct{}

func (as authorizationService) GenerateSHA256Key() (string, error) {
	// Gera uma sequência aleatória de bytes
	randomBytes := make([]byte, 32) // 32 bytes = 256 bits
	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		return "", err
	}

	// Calcula o hash SHA-256 da sequência aleatória de bytes
	hash := sha256.New()
	hash.Write(randomBytes)
	hashBytes := hash.Sum(nil)

	// Converte o hash para uma string hexadecimal
	hashString := hex.EncodeToString(hashBytes)

	return hashString, nil
}

func (as authorizationService) generateJWTToken(keyId uuid.UUID) (string, error) {
    // Defina a duração do token
    tokenExpiry := time.Now().Add(24 * time.Hour)

    // Crie o token JWT
    claims := jwt.MapClaims{
        "key_id": keyId.String(),
        "exp":    tokenExpiry.Unix(),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

    hash, err := as.GenerateSHA256Key()
    if err != nil {
       return "", err
    }
    fmt.Println("hash:", hash)
    secretKey := []byte(hash)
    tokenString, err := token.SignedString(secretKey)
    if err != nil {
        return "", err
    }
    fmt.Println("key:", secretKey)
    return tokenString, nil
}

func main() {
    // Crie uma instância do serviço de autorização
    authService := authorizationService{}

    // Gere um UUID para o keyId
    keyId := uuid.New()

    // Gere o token JWT
    token, err := authService.generateJWTToken(keyId)
    if err != nil {
        fmt.Println("Erro ao gerar o token:", err)
        return
    }

    fmt.Println("Token JWT gerado:", token)
}
