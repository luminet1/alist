package errs

import "errors"

var (
	EmptyUsername      = errors.New("用户名不能为空")
	EmptyPassword      = errors.New("密码不能为空")
	WrongPassword      = errors.New("密码不正确")
	DeleteAdminOrGuest = errors.New("无法删除管理员或游客")
)
