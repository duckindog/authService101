package handler

import (
	"encoding/json"
	"net/http"
	"authService101/internal/service"
	"authService101/internal/model"
)

type OAuth2Handler struct { 
	service service.OAuth2Service
}

func NewOAuth2Handler(oauthService service.OAuth2Service) *OAuth2Handler {
	return &OAuth2Handler{service: oauthService}
}

func (h *OAuth2Handler) GGRegister(w http.ResponseWriter, r *http.Request) {
	var req model.GGCode
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.service.GGRegister(r.Context(), req.Code); err != nil {
		h.sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *OAuth2Handler) GGLogin(w http.ResponseWriter, r *http.Request) {
	var req model.GGCode
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	access, refresh, email, err := h.service.GGLogin(r.Context(), req.Code)
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
		Email:        email,
	}, http.StatusOK)
}

func (h *OAuth2Handler) GGRefresh(w http.ResponseWriter, r *http.Request) {
	var req model.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	access, refresh, err := h.service.GGRefresh(r.Context(), req.RefreshToken)
	if err != nil {
		h.sendError(w, "invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	h.sendJSON(w, model.AuthResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	}, http.StatusOK)
}

func (h *OAuth2Handler) GGLogout(w http.ResponseWriter, r *http.Request) {
	var req model.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.service.GGLogout(r.Context(), req.RefreshToken); err != nil {
		h.sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *OAuth2Handler) GGCallBack(w http.ResponseWriter, r *http.Request) {
	
}

func (h *OAuth2Handler) sendJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *OAuth2Handler) sendError(w http.ResponseWriter, message string, status int) {
	h.sendJSON(w, map[string]string{"error": message}, status)
}