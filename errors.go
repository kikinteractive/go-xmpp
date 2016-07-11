// RFC 3290 9.3. Stanza Errors.
package xmpp

import "errors"

// XMPP error conditions.
var (
	ErrBadRequest            = errors.New("bad request")
	ErrConflict              = errors.New("conflict")
	ErrFeatureNotImplemented = errors.New("feature not implemented")
	ErrForbidden             = errors.New("forbidden")
	ErrGone                  = errors.New("gone")
	ErrInternalServerError   = errors.New("internal server error")
	ErrItemNotFound          = errors.New("item not found")
	ErrJIDMalformed          = errors.New("jid malformed")
	ErrNotAcceptable         = errors.New("not ccceptable")
	ErrNotAllowed            = errors.New("not allowed")
	ErrNotAuthorized         = errors.New("not authorized")
	ErrPaymentRequired       = errors.New("payment required")
	ErrRecipientUnavailable  = errors.New("recipient unavailable")
	ErrRedirect              = errors.New("redirect")
	ErrRegistrationRequired  = errors.New("registration required")
	ErrRemoteServerNotFound  = errors.New("remote server not found")
	ErrRemoteServerTimeout   = errors.New("remote server timeout")
	ErrResourceConstraint    = errors.New("resource constraint")
	ErrServiceUnavailable    = errors.New("service unavailable")
	ErrSubscriptionRequired  = errors.New("subscription required")
	ErrUndefinedCondition    = errors.New("undefined condition")
	ErrUnexpectedRequest     = errors.New("unexpected request")
)

func mapErrorCondition(condition string) error {
	var e error
	switch condition {
	case "bad-request":
		e = ErrBadRequest
	case "conflict":
		e = ErrConflict
	case "feature-not-implemented":
		e = ErrFeatureNotImplemented
	case "forbidden":
		e = ErrForbidden
	case "gone":
		e = ErrGone
	case "internal-server-error":
		e = ErrInternalServerError
	case "item-not-found":
		e = ErrItemNotFound
	case "jid-malformed":
		e = ErrJIDMalformed
	case "not-acceptable":
		e = ErrNotAcceptable
	case "not-allowed":
		e = ErrNotAllowed
	case "not-authorized":
		e = ErrNotAuthorized
	case "payment-required":
		e = ErrPaymentRequired
	case "recipient-unavailable":
		e = ErrRecipientUnavailable
	case "redirect":
		e = ErrRedirect
	case "registration-required":
		e = ErrRegistrationRequired
	case "remote-server-not-found":
		e = ErrRemoteServerNotFound
	case "remote-server-timeout":
		e = ErrRemoteServerTimeout
	case "resource-constraint":
		e = ErrResourceConstraint
	case "service-unavailable":
		e = ErrServiceUnavailable
	case "subscription-required":
		e = ErrSubscriptionRequired
	case "undefined-condition":
		e = ErrUndefinedCondition
	default:
		e = errors.New("unknown error condition: " + condition)
	}
	return e
}
