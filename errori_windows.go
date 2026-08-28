//go:build windows

// netools - mappatura errori di rete per Windows (Winsock)
//
// Copyright (C) 2026 Silvestro Scuderi
// Licenza GPLv3 - vedi il file LICENSE

package main

import (
	"errors"
	"syscall"
)

// Codici Winsock. Le costanti errno POSIX esistono anche su Windows
// per compatibilita' sorgente, ma hanno valori diversi da quelli che
// lo stack di rete restituisce davvero: vanno confrontati questi.
const (
	wsaeconnrefused = syscall.Errno(10061) // WSAECONNREFUSED
	wsaehostunreach = syscall.Errno(10065) // WSAEHOSTUNREACH
	wsaenetunreach  = syscall.Errno(10051) // WSAENETUNREACH
	wsaemfile       = syscall.Errno(10024) // WSAEMFILE
)

// rifiutoEsplicito riconosce il RST ricevuto dal peer.
func rifiutoEsplicito(err error) bool {
	return errors.Is(err, wsaeconnrefused) ||
		errors.Is(err, syscall.ECONNREFUSED)
}

// hostIrraggiungibile riconosce l'ICMP host unreachable.
func hostIrraggiungibile(err error) bool {
	return errors.Is(err, wsaehostunreach) ||
		errors.Is(err, syscall.EHOSTUNREACH)
}

// reteIrraggiungibile riconosce l'ICMP network unreachable.
func reteIrraggiungibile(err error) bool {
	return errors.Is(err, wsaenetunreach) ||
		errors.Is(err, syscall.ENETUNREACH)
}

// descrittoriEsauriti riconosce il limite locale sui socket disponibili.
func descrittoriEsauriti(err error) bool {
	return errors.Is(err, wsaemfile) || errors.Is(err, syscall.EMFILE)
}
