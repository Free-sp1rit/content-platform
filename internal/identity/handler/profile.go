package handler

import (
	"net/http"
	"strconv"

	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
	"github.com/Free-sp1rit/content-platform/internal/platform/httpx"
	"github.com/Free-sp1rit/content-platform/internal/platform/requestid"
)

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(r)
	if !ok || !h.available() {
		h.writeError(r.Context(), w, internalHandlerError())
		return
	}
	result, err := h.service.Me(r.Context(), identityservice.MeInput{
		UserID: principal.UserID, SessionID: principal.SessionID,
		RequestID: requestid.FromContext(r.Context()),
	})
	if err != nil {
		h.writeError(r.Context(), w, err)
		return
	}
	httpx.WriteData(r.Context(), w, http.StatusOK, newUserResponse(result))
}

func (h *Handler) PublicUser(w http.ResponseWriter, r *http.Request) {
	targetID, ok := parsePathID(r.PathValue("id"))
	if !ok {
		h.writeError(r.Context(), w, validationHandlerError())
		return
	}
	if !h.available() {
		h.writeError(r.Context(), w, internalHandlerError())
		return
	}
	result, err := h.service.PublicUser(r.Context(), identityservice.PublicUserInput{
		UserID: targetID, RequestID: requestid.FromContext(r.Context()),
	})
	if err != nil {
		h.writeError(r.Context(), w, err)
		return
	}
	httpx.WriteData(r.Context(), w, http.StatusOK, newPublicUserResponse(result))
}

func (h *Handler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(r)
	if !ok || !h.available() {
		h.writeError(r.Context(), w, internalHandlerError())
		return
	}
	var request updateMeRequest
	if !h.decode(w, r, &request) {
		return
	}
	input := identityservice.UpdateMeInput{
		UserID: principal.UserID, SessionID: principal.SessionID,
		RequestID: requestid.FromContext(r.Context()),
	}
	if request.DisplayName != nil {
		input.DisplayName = identityservice.SetField(*request.DisplayName)
	}
	if request.Bio != nil {
		input.Bio = identityservice.SetField(*request.Bio)
	}
	result, err := h.service.UpdateMe(r.Context(), input)
	if err != nil {
		h.writeError(r.Context(), w, err)
		return
	}
	httpx.WriteData(r.Context(), w, http.StatusOK, newUserResponse(result))
}

func (h *Handler) DeleteMe(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(r)
	if !ok || !h.available() {
		h.writeError(r.Context(), w, internalHandlerError())
		return
	}
	result, err := h.service.DeleteMe(r.Context(), identityservice.DeleteMeInput{
		UserID: principal.UserID, SessionID: principal.SessionID,
		RequestID: requestid.FromContext(r.Context()),
	})
	if err != nil {
		h.writeError(r.Context(), w, err)
		return
	}
	httpx.WriteData(r.Context(), w, http.StatusOK, deleteResponse{Deleted: result.Deleted})
}

func parsePathID(raw string) (int64, bool) {
	if raw == "" || raw[0] < '1' || raw[0] > '9' {
		return 0, false
	}
	for index := 1; index < len(raw); index++ {
		if raw[index] < '0' || raw[index] > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 || strconv.FormatInt(value, 10) != raw {
		return 0, false
	}
	return value, true
}
