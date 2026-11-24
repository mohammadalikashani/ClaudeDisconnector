//go:build windows

package core

import (
	"context"
	"net"
	"os"
	"strings"
)

// dialLocal opens a named pipe (\\.\pipe\...) or an AF_UNIX socket (Windows 10+).
func dialLocal(ctx context.Context, path string) (net.Conn, error) {
	if strings.HasPrefix(path, `\\.\pipe\`) || strings.HasPrefix(path, `//./pipe/`) {
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		return pipeConn{f}, nil
	}
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}

// pipeConn adapts a named-pipe file to net.Conn (deadlines come from *os.File).
type pipeConn struct{ *os.File }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

func (pipeConn) LocalAddr() net.Addr  { return pipeAddr{} }
func (pipeConn) RemoteAddr() net.Addr { return pipeAddr{} }
