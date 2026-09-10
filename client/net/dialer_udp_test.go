//go:build !ios

package net

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/net/hooks"
)

func TestDialerUDPDatagramsAndCleanup(t *testing.T) {
	for _, useDialUDP := range []bool{false, true} {
		name := "DialContext"
		if useDialUDP {
			name = "DialUDP"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv(envDisableCustomRouting, "false")
			server, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, server.Close()) })
			require.NoError(t, server.SetDeadline(time.Now().Add(time.Second)))

			var dialID, closeID hooks.ConnectionID
			hooks.AddWriteHook(func(id hooks.ConnectionID, _ netip.Prefix) error {
				dialID = id
				return nil
			})
			t.Cleanup(hooks.RemoveWriteHooks)
			hooks.AddCloseHook(func(id hooks.ConnectionID) error {
				closeID = id
				return nil
			})
			t.Cleanup(hooks.RemoveCloseHooks)

			var conn net.Conn
			if useDialUDP {
				remote, resolveErr := net.ResolveUDPAddr("udp", server.LocalAddr().String())
				require.NoError(t, resolveErr)
				conn, err = DialUDP("udp", nil, remote)
			} else {
				conn, err = NewDialer().DialContext(t.Context(), "udp", server.LocalAddr().String())
			}
			require.NoError(t, err)
			t.Cleanup(func() {
				if closeID == "" {
					assert.NoError(t, conn.Close())
				}
			})
			require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
			require.NotEmpty(t, dialID, "dial must register its routing hooks")
			_, err = conn.Write([]byte("query"))
			require.NoError(t, err)
			buf := make([]byte, 64)
			n, peer, err := server.ReadFrom(buf)
			require.NoError(t, err)
			assert.Equal(t, "query", string(buf[:n]), "server must receive an intact datagram")
			_, err = server.WriteTo([]byte("answer"), peer)
			require.NoError(t, err)
			packetConn, ok := conn.(net.PacketConn)
			require.True(t, ok, "resolver must recognize a datagram connection")
			n, _, err = packetConn.ReadFrom(buf)
			require.NoError(t, err)
			assert.Equal(t, "answer", string(buf[:n]), "caller must receive the response datagram")
			require.NoError(t, conn.Close())
			assert.Equal(t, dialID, closeID, "close must release the same routing registration")
		})
	}
}
