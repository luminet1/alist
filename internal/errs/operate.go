package errs

import "errors"

var (
	PermissionDenied = errors.New("权限被拒绝")
)
