//go:build !windows

package core

import (
	"context"
	"net"
)

func dialLocal(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}
