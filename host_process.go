package qjs

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ProcessExitError reports a JavaScript process.exit() without terminating the embedding process.
type ProcessExitError struct {
	Code int
}

func (e *ProcessExitError) Error() string {
	return fmt.Sprintf("JavaScript requested process exit with code %d", e.Code)
}

func (s *hostRuntimeState) processExit(this *This) (*Value, error) {
	code := 0
	if args := this.Args(); len(args) > 0 {
		code = int(args[0].Int64())
	}
	this.Context().runtime.requestProcessExit(code)
	return nil, &ProcessExitError{Code: code}
}

func (s *hostRuntimeState) stdioWrite(this *This) (*Value, error) {
	args := this.Args()
	if len(args) < 2 {
		return nil, errors.New("stream write requires a descriptor and data")
	}
	var writer io.Writer
	switch args[0].Int64() {
	case 1:
		writer = s.config.stdout
	case 2:
		writer = s.config.stderr
	default:
		return nil, fmt.Errorf("unsupported stream descriptor %d", args[0].Int64())
	}
	data, err := jsValueToBytes(args[1])
	if err != nil {
		return nil, err
	}
	if writer == nil {
		return this.Context().NewBool(true), nil
	}
	_, err = writer.Write(data)
	if err != nil {
		return nil, err
	}
	return this.Context().NewBool(true), nil
}

func (s *hostRuntimeState) hashDigest(this *This) (*Value, error) {
	args := this.Args()
	if len(args) < 2 {
		return nil, errors.New("hash digest requires an algorithm and data")
	}
	algorithm := strings.ToLower(strings.ReplaceAll(args[0].String(), "-", ""))
	data, err := jsValueToBytes(args[1])
	if err != nil {
		return nil, err
	}
	var digest []byte
	switch algorithm {
	case "md5":
		sum := md5.Sum(data)
		digest = sum[:]
	case "sha1":
		sum := sha1.Sum(data)
		digest = sum[:]
	case "sha256":
		sum := sha256.Sum256(data)
		digest = sum[:]
	case "sha384":
		sum := sha512.Sum384(data)
		digest = sum[:]
	case "sha512":
		sum := sha512.Sum512(data)
		digest = sum[:]
	default:
		return nil, fmt.Errorf("unsupported hash algorithm %q", args[0].String())
	}
	return this.Context().NewArrayBuffer(digest), nil
}
