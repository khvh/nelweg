package main

import (
	"github.com/khvh/nelweg/server"
)

var s server.Server

func main() {
	s = server.
		NewMockBuilder().
		WithConfig().
		Server()

	s.Run()
	// s = server.NewMock(
	// 	server.NewMockBuilder().WithConfig().Build()...,
	// )

}
