package main

import (
	"log"
	"net/http"
	"authService101/internal/config"
	"authService101/internal/db"
	"authService101/internal/handler"
	"authService101/internal/repository"
	"authService101/internal/service"
	"authService101/internal/token"
)

func main() {
	cfg := config.Load()
	
	database, err := db.NewPostgres(cfg.DBURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer database.Close()

	userRepo := repository.NewUserRepository(database)
	tokenRepo := repository.NewTokenRepository(database)
	
	jwtManager := token.NewJWTManager(cfg.JWTSecret, "auth-service-101", cfg.AccessTokenTTL)
	
	authService := service.NewAuthService(userRepo, tokenRepo, jwtManager, cfg.RefreshTokenTTL)
	authHandler := handler.NewAuthHandler(authService)
	
	mux := http.NewServeMux()
	
	// Serve static files from the "web" directory
	fs := http.FileServer(http.Dir("web"))
	mux.Handle("/", fs)

	mux.HandleFunc("/auth/register", authHandler.Register)
	mux.HandleFunc("/auth/login", authHandler.Login)
	mux.HandleFunc("/auth/refresh", authHandler.Refresh)
	mux.HandleFunc("/auth/logout", authHandler.Logout)

	// Wrap with CORS middleware
	corsHandler := corsMiddleware(mux)

	log.Printf("Server starting on port %s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, corsHandler); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
