package handler

import (
	"encoding/json"
	"net/http"
	"authService101/internal/service"
	"authService101/internal/model"
)

type AuthHandler struct {
	service service.AuthService
}

func NewAuthHandler(authService service.AuthService) *AuthHandler {
	return &AuthHandler{service: authService}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req model.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.service.Register(r.Context(), req.Email, req.Password); err != nil {
		h.sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	access, refresh, err := h.service.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		status := http.StatusInternalServerError
		if err == service.ErrInvalidCredentials {
			status = http.StatusUnauthorized
		}
		h.sendError(w, err.Error(), status)
		return
	}

	h.sendJSON(w, model.AuthResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	}, http.StatusOK)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req model.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	access, refresh, err := h.service.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		h.sendError(w, "invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	h.sendJSON(w, model.AuthResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	}, http.StatusOK)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req model.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.service.Logout(r.Context(), req.RefreshToken); err != nil {
		h.sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) sendJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *AuthHandler) sendError(w http.ResponseWriter, message string, status int) {
	h.sendJSON(w, map[string]string{"error": message}, status)
}