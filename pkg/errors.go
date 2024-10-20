package pkg

import "errors"

var ErrNetBinaryNotFound = errors.New("no binary found for the current OS and Arch")
