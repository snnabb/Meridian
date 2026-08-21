package main

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type queuedListener struct {
	connections chan net.Conn
	done        chan struct{}
	closeOnce   sync.Once
}

func newQueuedListener() *queuedListener {
	return &queuedListener{
		connections: make(chan net.Conn, 4),
		done:        make(chan struct{}),
	}
}

func (l *queuedListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *queuedListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (l *queuedListener) Addr() net.Addr { return testAddr("queued-listener") }

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

type acceptResult struct {
	conn net.Conn
	err  error
}

func asyncAccept(listener net.Listener) <-chan acceptResult {
	result := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		result <- acceptResult{conn: conn, err: err}
	}()
	return result
}

func requireAcceptBlocked(t *testing.T, result <-chan acceptResult) {
	t.Helper()
	select {
	case got := <-result:
		if got.conn != nil {
			got.conn.Close()
		}
		t.Fatalf("Accept returned before a permit was released: %v", got.err)
	case <-time.After(50 * time.Millisecond):
	}
}

func requireAccepted(t *testing.T, result <-chan acceptResult) net.Conn {
	t.Helper()
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("Accept: %v", got.err)
		}
		return got.conn
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Accept")
		return nil
	}
}

func TestLimitListenerReleasesOnePermitPerConnection(t *testing.T) {
	base := newQueuedListener()
	listener := limitListener(base, 1)
	t.Cleanup(func() { listener.Close() })

	serverOne, clientOne := net.Pipe()
	serverTwo, clientTwo := net.Pipe()
	serverThree, clientThree := net.Pipe()
	t.Cleanup(func() {
		clientOne.Close()
		clientTwo.Close()
		clientThree.Close()
	})
	base.connections <- serverOne
	base.connections <- serverTwo
	base.connections <- serverThree

	first := requireAccepted(t, asyncAccept(listener))
	secondResult := asyncAccept(listener)
	requireAcceptBlocked(t, secondResult)

	if err := first.Close(); err != nil {
		t.Fatalf("close first connection: %v", err)
	}
	second := requireAccepted(t, secondResult)

	// A repeated Close must not release a second permit.
	_ = first.Close()
	thirdResult := asyncAccept(listener)
	requireAcceptBlocked(t, thirdResult)

	if err := second.Close(); err != nil {
		t.Fatalf("close second connection: %v", err)
	}
	third := requireAccepted(t, thirdResult)
	if err := third.Close(); err != nil {
		t.Fatalf("close third connection: %v", err)
	}
}

func TestLimitListenerCloseUnblocksWaitingAccept(t *testing.T) {
	base := newQueuedListener()
	listener := limitListener(base, 1)

	server, client := net.Pipe()
	defer client.Close()
	base.connections <- server
	accepted := requireAccepted(t, asyncAccept(listener))
	defer accepted.Close()

	waiting := asyncAccept(listener)
	requireAcceptBlocked(t, waiting)
	if err := listener.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case got := <-waiting:
		if !errors.Is(got.err, net.ErrClosed) {
			t.Fatalf("waiting Accept error = %v, want net.ErrClosed", got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener close did not unblock Accept")
	}
}
