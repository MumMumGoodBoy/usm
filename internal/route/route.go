package route

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/mummumgoodboy/usm/internal/auth"
	"github.com/mummumgoodboy/usm/internal/dto"
	"github.com/mummumgoodboy/usm/internal/model"
	"github.com/mummumgoodboy/usm/internal/service"
	"github.com/mummumgoodboy/verify"
)

func JsonHeaderMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next(w, r)
	}
}

func CreateUserRoute(userService *service.UserService) {
	http.HandleFunc("POST /auth/login", JsonHeaderMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var input model.LoginUserInput
		err := json.NewDecoder(r.Body).Decode(&input)
		if err != nil {
			resp := dto.Error{
				Error: "error while decoding request body",
				Code:  "bad_input",
			}
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resp)
			return
		}

		if input.UserName == "" || input.Password == "" {
			resp := dto.Error{
				Error: "username or password is empty",
				Code:  "bad_input",
			}
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resp)
			return
		}

		signed, err := userService.LoginUser(input)
		if err != nil {
			if errors.Is(err, service.ErrWrongCredentials) {
				resp := dto.Error{
					Error: "wrong username or password",
					Code:  "wrong_credentials",
				}
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(resp)
				return
			}

			slog.Warn("error while logging in",
				"error", err)
			resp := dto.Error{
				Error: "error while logging in",
				Code:  "internal_error",
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(resp)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(dto.LoginResponse{
			Token: signed,
		})
	}))

	http.HandleFunc("POST /auth/register", JsonHeaderMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var input model.RegisterUserInput
		err := json.NewDecoder(r.Body).Decode(&input)
		if err != nil {
			resp := dto.Error{
				Error: "error while decoding request body",
				Code:  "bad_input",
			}
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(resp)
			return
		}
		if input.UserName == "" ||
			input.Email == "" ||
			input.Password == "" ||
			input.FirstName == "" ||
			input.LastName == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(dto.Error{
				Error: "one or more fields are empty",
				Code:  "bad_input",
			})
		}

		err = userService.RegisterUser(input)
		if err != nil {
			if errors.Is(err, service.ErrUserExists) {
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(dto.Error{
					Error: "user already exists",
					Code:  "user_exists",
				})
				return
			}

			if errors.Is(err, service.ErrEmailExists) {
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(dto.Error{
					Error: "email already exists",
					Code:  "email_exists",
				})
				return
			}
			slog.Warn("error while registering user",
				"error", err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(dto.Error{
				Error: "error while registering user",
				Code:  "internal_error",
			})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}))

	// TODO: Add credentials check
	http.HandleFunc("GET /users", JsonHeaderMiddleware(func(w http.ResponseWriter, r *http.Request) {
		// get ids from query params
		idsStr, ok := r.URL.Query()["id"]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(dto.Error{
				Error: "id is required",
				Code:  "bad_input",
			})
			return
		}

		ids := make([]uint, 0, len(idsStr))
		for _, idStr := range idsStr {
			id, err := strconv.Atoi(idStr)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(dto.Error{
					Error: "id must be an integer",
					Code:  "bad_input",
				})
				return
			}
			if id < 1 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(dto.Error{
					Error: "id must be greater than 0",
					Code:  "bad_input",
				})
			}
			ids = append(ids, uint(id))
		}

		users, err := userService.GetUsersById(ids)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(dto.Error{
				Error: "error while fetching users",
				Code:  "internal_error",
			})
			return
		}

		resp := make([]dto.UserCommonInfo, 0, len(users))
		for _, user := range users {
			resp = append(resp, dto.UserCommonInfo{
				UserId:    user.ID,
				UserName:  user.UserName,
				FirstName: user.FirstName,
				LastName:  user.LastName,
			})
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
}

func MeRoute(userService *service.UserService, verifier *verify.JWTVerifier) {
	http.HandleFunc("GET /me", JsonHeaderMiddleware(func(w http.ResponseWriter, r *http.Request) {
		token, ok := auth.GetTokenHeader(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(dto.Error{
				Error: "token is required in Authorization header",
				Code:  "unauthorized",
			})
			return
		}

		claims, err := verifier.Verify(token)
		if err != nil {
			slog.Warn("error while verifying token",
				"token", token,
				"error", err)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(dto.Error{
				Error: "invalid token",
				Code:  "unauthorized",
			})
			return
		}

		user, err := userService.GetUserById(claims.UserId)
		if err != nil {
			slog.Warn("error while fetching user",
				"userId", claims.UserId,
				"error", err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(dto.Error{
				Error: "error while fetching user",
				Code:  "internal_error",
			})
			return
		}

		resp := dto.MeInfo{
			UserId:    user.ID,
			UserName:  user.UserName,
			FirstName: user.FirstName,
			LastName:  user.LastName,
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))

	http.HandleFunc("PUT /me", JsonHeaderMiddleware(func(w http.ResponseWriter, r *http.Request) {
		token, ok := auth.GetTokenHeader(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(dto.Error{
				Error: "token is required in Authorization header",
				Code:  "unauthorized",
			})
			return
		}

		claims, err := verifier.Verify(token)
		if err != nil {
			slog.Warn("error while verifying token",
				"token", token,
				"error", err)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(dto.Error{
				Error: "invalid token",
				Code:  "unauthorized",
			})
			return
		}

		user, err := userService.GetUserById(claims.UserId)
		if err != nil {
			slog.Warn("error while fetching user",
				"userId", claims.UserId,
				"error", err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(dto.Error{
				Error: "error while fetching user",
				Code:  "internal_error",
			})
			return
		}

		var req dto.UpdateUserRequest
		err = json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			slog.Warn("error while decoding request",
				"error", err)
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(dto.Error{
				Error: "error while decoding request",
				Code:  "bad_input",
			})
			return
		}

		user.FirstName = req.FirstName
		user.LastName = req.LastName

		err = userService.UpdateUser(user)
		if err != nil {
			slog.Warn("error while updating user",
				"userId", user.ID,
				"error", err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(dto.Error{
				Error: "error while updating user",
				Code:  "internal_error",
			})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}))

	http.HandleFunc("PATCH /me/password", JsonHeaderMiddleware(func(w http.ResponseWriter, r *http.Request) {
		token, ok := auth.GetTokenHeader(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(dto.Error{
				Error: "token is required in Authorization header",
				Code:  "unauthorized",
			})
			return
		}

		claims, err := verifier.Verify(token)
		if err != nil {
			slog.Warn("error while verifying token",
				"token", token,
				"error", err)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(dto.Error{
				Error: "invalid token",
				Code:  "unauthorized",
			})
			return
		}

		var req dto.ChangePasswordRequest
		err = json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			slog.Warn("error while decoding request",
				"error", err)
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(dto.Error{
				Error: "error while decoding request",
				Code:  "bad_input",
			})
			return
		}

		err = userService.ChangePassword(claims.UserId, req.OldPassword, req.NewPassword)
		if err != nil {
			if errors.Is(err, service.ErrWrongCredentials) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(dto.Error{
					Error: "wrong password",
					Code:  "wrong_password",
				})
				return
			}

			slog.Warn("error while changing password",
				"userId", claims.UserId,
				"error", err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(dto.Error{
				Error: "error while changing password",
				Code:  "internal_error",
			})
		}

		w.WriteHeader(http.StatusNoContent)
	}))
}
