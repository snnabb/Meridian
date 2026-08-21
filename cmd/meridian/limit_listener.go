package main

import (
	"net"
	"sync"
)

// limitListener caps the number of accepted connections that have not yet
// been closed. Waiting Accept calls are released when the listener is closed.
func limitListener(listener net.Listener, maxConnections int) net.Listener {
	if maxConnections <= 0 {
		panic("maxConnections must be positive")
	}
	return &connectionLimitListener{
		Listener: listener,
		permits:  make(chan struct{}, maxConnections),
		done:     make(chan struct{}),
	}
}

type connectionLimitListener struct {
	net.Listener
	permits   chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func (l *connectionLimitListener) Accept() (net.Conn, error) {
	select {
	case l.permits <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}

	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.permits
		return nil, err
	}
	return &connectionLimitConn{
		Conn:    conn,
		release: func() { <-l.permits },
	}, nil
}

func (l *connectionLimitListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		l.closeErr = l.Listener.Close()
	})
	return l.closeErr
}

type connectionLimitConn struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func (c *connectionLimitConn) Close() error {
	err := c.Conn.Close()
	c.releaseOnce.Do(c.release)
	return err
}
