package tokens

import "errors"

// Sentinel errors used across issuing and validation flows. Callers can use
// errors.Is(err, ErrXxx) to branch on specific reasons without relying on types.
var (
	// ErrDeviceOccupied indicates the target device is already occupied by another user
	// when multi-user is not allowed for the device.
	ErrDeviceOccupied = errors.New("device already occupied by another user")

	// ErrUserLoggedInElsewhere indicates the same user has active sessions on other devices
	// while cross-device replacement is disabled.
	ErrUserLoggedInElsewhere = errors.New("user already logged in on another device")

	// ErrRefreshNotCurrent indicates a provided refresh token is not the current one mapped
	// for the (uid, deviceID), usually due to being replaced by a newer login.
	ErrRefreshNotCurrent = errors.New("refresh token is not current for this device")
)
