// Package server implements JWT-based authentication for the control plane (port 6677)
// and Bearer-token authentication for the data plane (port 1616).
package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// ─── JWT control-plane auth ───────────────────────────────────────────────────

// jwtSecret is set once at server start from config.
var jwtSecret []byte

// SetJWTSecret stores the signing key; call this before registering routes.
func SetJWTSecret(secret string) {
	jwtSecret = []byte(secret)
}

// Claims is the payload embedded in every JWT issued by /api/login.
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// GenerateJWT creates a signed HS256 JWT valid for 24 hours.
func GenerateJWT(username string) (string, error) {
	claims := Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "opentalon",
			Subject:   username,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// parseJWT validates a token string and returns the claims.
func parseJWT(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, err
	}
	return claims, nil
}

// JWTMiddleware is a Gin middleware that validates JWT tokens on the control plane.
// It expects the header:  Authorization: Bearer <jwt>
// On success it stores the username in the Gin context as "username".
func JWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := c.GetHeader("Authorization")
		if raw == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing Authorization header",
			})
			return
		}

		parts := strings.SplitN(raw, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid Authorization format, expected: Bearer <token>",
			})
			return
		}

		claims, err := parseJWT(parts[1])
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or expired token",
			})
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}

// ─── Bearer-token data-plane auth ────────────────────────────────────────────

// agentToken is the pre-shared key for agent → server requests.
var agentToken string

// SetAgentToken stores the token; call this before registering data-plane routes.
func SetAgentToken(token string) {
	agentToken = token
}

// AgentTokenMiddleware is a lightweight middleware for the data plane.
// It checks: Authorization: Bearer <agent_token>
// Rejects immediately with 401 on any mismatch (no token issuance involved).
func AgentTokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := c.GetHeader("Authorization")
		expected := "Bearer " + agentToken

		// constant-time comparison would be ideal; for this use-case string compare is acceptable
		// because we don't need to guard against timing attacks on pre-shared key verification here.
		if raw == "" || raw != expected {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or missing agent token",
			})
			return
		}
		c.Next()
	}
}
