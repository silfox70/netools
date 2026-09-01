// netools - identificazione dei servizi in ascolto
//
// Copyright (C) 2026 Silvestro Scuderi
// Licenza GPLv3 - vedi il file LICENSE

package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// attesaBanner e' il tempo concesso a un servizio per presentarsi
	// spontaneamente. Chi lo fa (ssh, smtp, ftp) invia il saluto
	// subito dopo l'handshake; oltre questa soglia si assume che il
	// servizio stia aspettando una richiesta.
	attesaBanner = 300 * time.Millisecond

	// lunghezzaBanner limita cio' che viene mostrato sulla riga di
	// output: serve a identificare il servizio, non a riprodurne la
	// risposta completa.
	lunghezzaBanner = 60

	// letturaMax limita i byte letti dalla rete, a prescindere da
	// quanto il servizio invii.
	letturaMax = 4096
)

// porteTLS elenca le porte su cui il traffico e' cifrato per
// convenzione: su queste si va direttamente di handshake, senza
// perdere tempo ad attendere un saluto in chiaro che non arrivera'.
var porteTLS = map[int]bool{
	443: true, 465: true, 636: true, 993: true, 995: true,
	5989: true, 8443: true, 9443: true,
}

// porteHTTPSuTLS sono quelle su cui, completato l'handshake, ha senso
// inviare anche una richiesta HTTP per ricavare l'identita' del server.
var porteHTTPSuTLS = map[int]bool{
	443: true, 5989: true, 8443: true, 9443: true,
}

// nonStampabili individua i byte che manderebbero in confusione il
// terminale. Alcuni servizi rispondono con dati binari, e riversarli
// sullo schermo senza filtro puo' alterare la sessione.
var nonStampabili = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)

// leggiBanner tenta di identificare il servizio in ascolto su una
// porta gia' risultata aperta.
//
// La strategia segue il comportamento dei protocolli piu' diffusi:
// alcuni si presentano da soli appena la connessione si apre, altri
// restano in attesa di una richiesta, altri ancora non dicono nulla
// in chiaro. Si prova nell'ordine, dal caso meno invasivo al piu'
// esplicito.
func leggiBanner(ip string, porta int, timeout time.Duration) string {
	if porteTLS[porta] {
		return bannerTLS(ip, porta, timeout)
	}

	indirizzo := net.JoinHostPort(ip, strconv.Itoa(porta))
	conn, err := net.DialTimeout("tcp", indirizzo, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Primo tentativo: il servizio si presenta da solo.
	conn.SetReadDeadline(time.Now().Add(attesaBanner))
	if b := leggiRiga(conn); b != "" {
		return b
	}

	// Nessun saluto spontaneo: si prova una richiesta HTTP minima.
	// HEAD anziche' GET perche' chiede solo gli header, evitando di
	// scaricare il corpo della pagina.
	conn.SetWriteDeadline(time.Now().Add(timeout))
	richiesta := richiestaHTTP(ip)

	if _, err := conn.Write([]byte(richiesta)); err != nil {
		return ""
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	return bannerHTTP(conn)
}

// bannerTLS completa l'handshake e ricava l'identita' del servizio
// dai dati della sessione cifrata.
func bannerTLS(ip string, porta int, timeout time.Duration) string {
	indirizzo := net.JoinHostPort(ip, strconv.Itoa(porta))

	dialer := &net.Dialer{Timeout: timeout}

	// La verifica del certificato e' volutamente disattivata: le
	// interfacce di gestione usano quasi sempre certificati
	// autofirmati, e qui l'obiettivo e' identificare il servizio,
	// non stabilire un canale sicuro.
	conn, err := tls.DialWithDialer(dialer, "tcp", indirizzo,
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return ""
	}
	defer conn.Close()

	stato := conn.ConnectionState()

	var parti []string
	parti = append(parti, nomeVersioneTLS(stato.Version))

	// Il nome comune del certificato identifica spesso l'apparato
	// meglio di qualsiasi banner applicativo.
	if len(stato.PeerCertificates) > 0 {
		cn := stato.PeerCertificates[0].Subject.CommonName
		if cn != "" {
			parti = append(parti, cn)
		}
	}

	// Sulle porte che parlano HTTP sotto TLS si prova comunque una
	// richiesta, per ricavare l'intestazione del server.
	if porteHTTPSuTLS[porta] {
		conn.SetWriteDeadline(time.Now().Add(timeout))

		if _, err := conn.Write([]byte(richiestaHTTP(ip))); err == nil {
			conn.SetReadDeadline(time.Now().Add(timeout))

			// Il solo codice di stato non aggiunge nulla a quanto
			// gia' dichiarato dalla porta e dal certificato: la
			// parte HTTP si tiene soltanto quando identifica
			// davvero il server.
			if h := bannerHTTP(conn); h != "" && !strings.HasPrefix(h, "HTTP/") {
				parti = append(parti, h)
			}
		}
	}

	return tronca(pulisci(strings.Join(parti, " | ")), lunghezzaBanner)
}

// richiestaHTTP compone una richiesta minima. Si usa HEAD anziche' GET
// perche' chiede soltanto gli header, senza far trasferire il corpo
// della pagina.
func richiestaHTTP(ip string) string {
	return fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\n"+
		"User-Agent: netools/%s\r\n\r\n", ip, versione)
}

// bannerHTTP estrae dalla risposta l'intestazione piu' utile a
// identificare il servizio.
func bannerHTTP(conn net.Conn) string {
	lettore := bufio.NewReader(&letturaLimitata{conn: conn, restanti: letturaMax})

	prima, err := lettore.ReadString('\n')
	if err != nil && prima == "" {
		return ""
	}
	prima = strings.TrimSpace(prima)

	// Se la prima riga non e' una risposta HTTP, il servizio parla
	// un altro protocollo: si restituisce cio' che ha detto.
	if !strings.HasPrefix(prima, "HTTP/") {
		return tronca(pulisci(prima), lunghezzaBanner)
	}

	var server string
	for i := 0; i < 30; i++ {
		riga, err := lettore.ReadString('\n')
		if err != nil {
			break
		}
		riga = strings.TrimSpace(riga)
		if riga == "" {
			break // fine degli header
		}
		if strings.HasPrefix(strings.ToLower(riga), "server:") {
			server = strings.TrimSpace(riga[7:])
			break
		}
	}

	if server != "" {
		return tronca(pulisci(server), lunghezzaBanner)
	}

	// Nessuna intestazione Server: resta il codice di stato, che dice
	// comunque che dall'altra parte c'e' un server web. Chi chiama
	// decide se valga la pena mostrarlo.
	return tronca(pulisci(prima), lunghezzaBanner)
}

// leggiRiga attende una riga di saluto dal servizio.
func leggiRiga(conn net.Conn) string {
	lettore := bufio.NewReader(&letturaLimitata{conn: conn, restanti: letturaMax})

	riga, err := lettore.ReadString('\n')
	if err != nil && riga == "" {
		return ""
	}

	riga = strings.TrimSpace(riga)
	if riga == "" {
		return ""
	}

	return tronca(pulisci(riga), lunghezzaBanner)
}

// letturaLimitata impedisce che un servizio malfunzionante o ostile
// faccia consumare memoria senza limite.
type letturaLimitata struct {
	conn     net.Conn
	restanti int
}

func (l *letturaLimitata) Read(p []byte) (int, error) {
	if l.restanti <= 0 {
		return 0, fmt.Errorf("limite di lettura raggiunto")
	}
	if len(p) > l.restanti {
		p = p[:l.restanti]
	}
	n, err := l.conn.Read(p)
	l.restanti -= n
	return n, err
}

// pulisci rimuove i caratteri di controllo e normalizza gli spazi.
func pulisci(s string) string {
	s = nonStampabili.ReplaceAllString(s, "")
	return strings.Join(strings.Fields(s), " ")
}

// nomeVersioneTLS traduce la costante numerica in una sigla leggibile.
func nomeVersioneTLS(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return "TLS?"
	}
}
