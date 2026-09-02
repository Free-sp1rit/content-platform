package handler

import (
	"net/http"
	"time"

	identityservice "github.com/Free-sp1rit/content-platform/internal/identity/service"
	"github.com/Free-sp1rit/content-platform/internal/platform/httpx"
	"github.com/Free-sp1rit/content-platform/internal/platform/requestid"
)

func (h *Handler) ChangeStatus(w http.ResponseWriter, r *http.Request) {
	targetID, ok := parsePathID(r.PathValue("id"))
	if !ok {
		h.writeError(r.Context(), w, validationHandlerError())
		return
	}
	principal, ok := h.principal(r)
	if !ok || !h.available() {
		h.writeError(r.Context(), w, internalHandlerError())
		return
	}
	var request changeStatusRequest
	if !h.decode(w, r, &request) {
		return
	}
	input := identityservice.ChangeUserStatusInput{
		ActorID: principal.UserID, ActorSessionID: principal.SessionID, TargetID: targetID,
		NewStatus: request.Status, RequestID: requestid.FromContext(r.Context()),
	}
	if request.Reason != nil {
		input.Reason = *request.Reason
	}
	if request.MutedUntil != nil {
		parsed, ok := parseStrictRFC3339(*request.MutedUntil)
		if !ok {
			h.writeError(r.Context(), w, validationHandlerError())
			return
		}
		normalized := parsed.UTC().Truncate(time.Second)
		input.MutedUntil = &normalized
	}
	result, err := h.service.ChangeUserStatus(r.Context(), input)
	if err != nil {
		h.writeError(r.Context(), w, err)
		return
	}
	httpx.WriteData(r.Context(), w, http.StatusOK, newUserResponse(result))
}

func parseStrictRFC3339(raw string) (time.Time, bool) {
	if !validRFC3339Syntax(raw) {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	return parsed, err == nil
}

func validRFC3339Syntax(raw string) bool {
	if len(raw) < len("2006-01-02T15:04:05Z") ||
		raw[4] != '-' || raw[7] != '-' || raw[10] != 'T' ||
		raw[13] != ':' || raw[16] != ':' {
		return false
	}
	for _, index := range [...]int{0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18} {
		if raw[index] < '0' || raw[index] > '9' {
			return false
		}
	}

	zoneStart := 19
	if raw[zoneStart] == '.' {
		zoneStart++
		fractionStart := zoneStart
		for zoneStart < len(raw) && raw[zoneStart] >= '0' && raw[zoneStart] <= '9' {
			zoneStart++
		}
		if zoneStart == fractionStart {
			return false
		}
	}
	zone := raw[zoneStart:]
	if zone == "Z" {
		return true
	}
	if len(zone) != len("+00:00") ||
		(zone[0] != '+' && zone[0] != '-') || zone[3] != ':' ||
		!twoDigits(zone[1], zone[2]) || !twoDigits(zone[4], zone[5]) {
		return false
	}
	hour := 10*(zone[1]-'0') + zone[2] - '0'
	minute := 10*(zone[4]-'0') + zone[5] - '0'
	return hour <= 23 && minute <= 59
}

func twoDigits(left, right byte) bool {
	return left >= '0' && left <= '9' && right >= '0' && right <= '9'
}
