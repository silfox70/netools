//go:build !windows

// netools - mappatura errori di rete per sistemi POSIX
//
// Copyright (C) 2026 Silvestro Scuderi
// Licenza GPLv3 - vedi il file LICENSE

package main

import (
	"errors"
	"syscall"
)

// rifiutoEsplicito riconosce il RST ricevuto dal peer.
func rifiutoEsplicito(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// hostIrraggiungibile riconosce l'ICMP host unreachable.
func hostIrraggiungibile(err error) bool {
	return errors.Is(err, syscall.EHOSTUNREACH)
}

// reteIrraggiungibile riconosce l'ICMP network unreachable.
func reteIrraggiungibile(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH)
}

// descrittoriEsauriti riconosce il limite locale sui file descriptor.
func descrittoriEsauriti(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE)
}
