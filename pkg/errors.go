package pkg

import "errors"

var NetBinaryNotFound = errors.New("no binary found for the current OS and Arch")
