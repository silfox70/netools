//go:build !plan9

// netools - scoperta degli host attivi su una rete
//
// Copyright (C) 2026 Silvestro Scuderi
// Licenza GPLv3 - vedi il file LICENSE

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// porteSonda sono le porte usate per stabilire se un host e' attivo.
// Sono scelte fra quelle piu' comunemente in ascolto su sistemi di
// qualsiasi tipo, dai server agli apparati di rete.
var porteSonda = []int{22, 80, 443, 445, 3389}

// modoICMP indica come e' stato possibile aprire il socket ICMP.
type modoICMP int

const (
	icmpAssente modoICMP = iota // nessun socket disponibile
	icmpRaw                     // raw socket: richiede privilegi
	icmpDatagram                // socket non privilegiato
)

// EsitoHost raccoglie quanto rilevato su un singolo indirizzo.
type EsitoHost struct {
	IP        net.IP
	RispICMP  bool
	RttICMP   time.Duration
	Tentativo int // tentativo in cui e' arrivata la risposta ICMP (1 = primo)
	RispTCP   bool
	PortaTCP  int
	RttTCP    time.Duration
}

// Vivo indica se l'host ha dato un qualsiasi segno di vita.
func (e EsitoHost) Vivo() bool {
	return e.RispICMP || e.RispTCP
}

// eseguiScan e' il punto d'ingresso del sottocomando "scan".
// Restituisce il codice di uscita del programma.
func eseguiScan(cidr string, timeout time.Duration, concorrenza, tentativi int) int {
	indirizzi, err := espandiRete(cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rete non valida: %v\n", err)
		return 2
	}

	// Si tenta comunque l'apertura del socket, senza controllare
	// prima chi siamo: e' l'unico modo affidabile di sapere cosa e'
	// davvero consentito, e copre anche i casi intermedi come
	// CAP_NET_RAW assegnato al binario su Linux.
	conn, modo := apriICMP()
	if conn != nil {
		defer conn.Close()
	}

	fmt.Printf("%s %s - scansione della rete %s\n", nomeProgramma, versione, cidr)
	fmt.Printf("%d indirizzi, timeout %v, %d host contemporanei\n",
		len(indirizzi), timeout, concorrenza)

	switch modo {
	case icmpRaw:
		fmt.Printf("sonde: ICMP echo (%d tentativi) e TCP\n", tentativi)
	case icmpDatagram:
		fmt.Printf("sonde: ICMP echo non privilegiato (%d tentativi) e TCP\n", tentativi)
	default:
		fmt.Println("sonde: TCP soltanto")
		fmt.Println("ICMP non disponibile su questo sistema: servono privilegi")
		fmt.Println("di root, oppure CAP_NET_RAW sul binario. Gli host che")
		fmt.Println("rispondono solo al ping non verranno rilevati.")
	}
	fmt.Println()

	inizio := time.Now()

	esiti := make([]EsitoHost, len(indirizzi))
	for i, ip := range indirizzi {
		esiti[i].IP = ip
	}

	// Fase ICMP. ICMP non prevede ritrasmissione: un pacchetto perso
	// significa host dichiarato spento. Su collegamenti instabili
	// (wifi con segnale debole, apparati sotto carico) la perdita e'
	// abbastanza frequente da produrre falsi negativi, quindi gli
	// indirizzi silenziosi vengono ritentati. Ogni giro interroga
	// soltanto chi non ha ancora risposto, percio' il costo dei
	// tentativi successivi e' proporzionale ai silenziosi e non al
	// totale della rete.
	if conn != nil {
		daProvare := make([]int, len(indirizzi))
		for i := range daProvare {
			daProvare[i] = i
		}

		for t := 1; t <= tentativi && len(daProvare) > 0; t++ {
			risposte := sweepICMP(conn, modo, indirizzi, daProvare, t, timeout)

			var restanti []int
			for _, i := range daProvare {
				if rtt, ok := risposte[indirizzi[i].String()]; ok {
					esiti[i].RispICMP = true
					esiti[i].RttICMP = rtt
					esiti[i].Tentativo = t
				} else {
					restanti = append(restanti, i)
				}
			}
			daProvare = restanti
		}
	}

	// Fase TCP: eseguita sempre, anche sugli host che hanno gia'
	// risposto a ICMP, perche' i due canali possono essere filtrati
	// in modo indipendente. Qui non servono tentativi aggiuntivi: la
	// ritrasmissione del SYN e' gia' compito del kernel.
	sweepTCP(esiti, timeout, concorrenza)

	durata := time.Since(inizio)
	stampaScan(esiti, modo, tentativi, durata)
	return 0
}

// apriICMP tenta l'apertura nel modo migliore disponibile.
//
// Il raw socket preserva l'identificatore che scriviamo nel messaggio,
// e permette quindi di distinguere le nostre risposte da quelle
// destinate ad altri processi. Il socket non privilegiato non lo fa:
// il kernel sostituisce l'ID con un valore proprio e consegna al
// processo soltanto le risposte che gli competono, rendendo il filtro
// superfluo ma anche impossibile.
func apriICMP() (*icmp.PacketConn, modoICMP) {
	if c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
		return c, icmpRaw
	}

	// Disponibile senza privilegi su macOS, e su Linux quando il GID
	// dell'utente rientra in net.ipv4.ping_group_range.
	if c, err := icmp.ListenPacket("udp4", "0.0.0.0"); err == nil {
		return c, icmpDatagram
	}

	return nil, icmpAssente
}

// sweepICMP invia una echo request agli indirizzi indicati da daProvare
// e raccoglie le risposte fino allo scadere del tempo. Restituisce una
// mappa indirizzo -> tempo di andata e ritorno.
//
// Il numero di sequenza combina tentativo e indice dell'host, cosi' una
// risposta tardiva del giro precedente non viene scambiata per una
// risposta del giro in corso: senza questo accorgimento il tempo
// riportato sarebbe falsato.
func sweepICMP(conn *icmp.PacketConn, modo modoICMP, indirizzi []net.IP,
	daProvare []int, tentativo int, timeout time.Duration) map[string]time.Duration {

	risposte := make(map[string]time.Duration)
	id := os.Getpid() & 0xffff

	base := tentativo * len(indirizzi)
	invio := make(map[int]time.Time, len(daProvare))
	var mu sync.Mutex

	// L'invio non e' istantaneo: i pacchetti sono distanziati per non
	// saturare la coda di trasmissione. La scadenza tiene conto del
	// tempo complessivo di invio, altrimenti gli ultimi host avrebbero
	// meno tempo a disposizione dei primi.
	attesaInvio := time.Duration(len(daProvare)) * time.Millisecond
	scadenza := time.Now().Add(attesaInvio).Add(timeout)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		conn.SetReadDeadline(scadenza)

		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return // scadenza raggiunta
			}

			msg, err := icmp.ParseMessage(1, buf[:n])
			if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
				continue
			}

			echo, ok := msg.Body.(*icmp.Echo)
			if !ok {
				continue
			}

			// Sul raw socket arrivano anche le risposte destinate ad
			// altri processi e vanno scartate. Sul socket non
			// privilegiato il controllo non e' applicabile perche'
			// l'ID e' stato riscritto dal kernel, ma non serve: il
			// kernel consegna soltanto cio' che ci compete.
			if modo == icmpRaw && echo.ID != id {
				continue
			}

			// Il socket non privilegiato riporta il mittente come
			// net.UDPAddr, quello raw come net.IPAddr: si estrae
			// l'indirizzo in modo indipendente dal tipo.
			mittente := estraiIP(peer)
			if mittente == "" {
				continue
			}

			mu.Lock()
			partenza, atteso := invio[echo.Seq]
			if atteso {
				if _, gia := risposte[mittente]; !gia {
					risposte[mittente] = time.Since(partenza)
				}
			}
			mu.Unlock()
		}
	}()

	for _, i := range daProvare {
		seq := base + i

		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("netools")},
		}

		codificato, err := msg.Marshal(nil)
		if err != nil {
			continue
		}

		mu.Lock()
		invio[seq] = time.Now()
		mu.Unlock()

		conn.WriteTo(codificato, destinazione(indirizzi[i], modo))
		time.Sleep(time.Millisecond)
	}

	wg.Wait()
	return risposte
}

// destinazione costruisce l'indirizzo nella forma attesa dal socket:
// il socket non privilegiato lavora con net.UDPAddr, quello raw con
// net.IPAddr.
func destinazione(ip net.IP, modo modoICMP) net.Addr {
	if modo == icmpDatagram {
		return &net.UDPAddr{IP: ip}
	}
	return &net.IPAddr{IP: ip}
}

// estraiIP ricava l'indirizzo dal mittente, qualunque sia il tipo
// concreto restituito dal socket.
func estraiIP(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.String()
	case *net.IPAddr:
		return a.IP.String()
	default:
		return ""
	}
}

// sweepTCP prova le porte sonda su ogni host, con un limite di host
// verificati contemporaneamente. Ogni host in prova impegna tanti
// descrittori quante sono le porte sonda.
func sweepTCP(esiti []EsitoHost, timeout time.Duration, concorrenza int) {
	semaforo := make(chan struct{}, concorrenza)
	var wg sync.WaitGroup

	for i := range esiti {
		wg.Add(1)
		go func(indice int) {
			defer wg.Done()
			semaforo <- struct{}{}
			defer func() { <-semaforo }()

			vivo, porta, rtt := sondaTCP(esiti[indice].IP, timeout)
			if vivo {
				esiti[indice].RispTCP = true
				esiti[indice].PortaTCP = porta
				esiti[indice].RttTCP = rtt
			}
		}(i)
	}

	wg.Wait()
}

// sondaTCP prova tutte le porte sonda in parallelo su un singolo host.
// Una porta che accetta la connessione e una che risponde con RST sono
// entrambe prova di vita: nel secondo caso qualcuno ha comunque
// risposto, rifiutando.
func sondaTCP(ip net.IP, timeout time.Duration) (bool, int, time.Duration) {
	type esito struct {
		porta  int
		durata time.Duration
	}

	trovati := make(chan esito, len(porteSonda))
	var wg sync.WaitGroup

	for _, p := range porteSonda {
		wg.Add(1)
		go func(porta int) {
			defer wg.Done()

			indirizzo := net.JoinHostPort(ip.String(), strconv.Itoa(porta))
			avvio := time.Now()
			conn, err := net.DialTimeout("tcp", indirizzo, timeout)
			durata := time.Since(avvio)

			if err == nil {
				conn.Close()
				trovati <- esito{porta, durata}
				return
			}
			if rifiutoEsplicito(err) {
				trovati <- esito{porta, durata}
			}
		}(p)
	}

	wg.Wait()
	close(trovati)

	migliore := esito{}
	valido := false
	for e := range trovati {
		if !valido || e.durata < migliore.durata {
			migliore = e
			valido = true
		}
	}

	return valido, migliore.porta, migliore.durata
}

// espandiRete converte una notazione CIDR nell'elenco degli indirizzi
// utilizzabili, escludendo indirizzo di rete e broadcast.
func espandiRete(cidr string) ([]net.IP, error) {
	// Un indirizzo singolo senza prefisso viene trattato come /32.
	if !strings.Contains(cidr, "/") {
		ip := net.ParseIP(cidr)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("%q non e' un indirizzo IPv4 ne' una rete", cidr)
		}
		return []net.IP{ip.To4()}, nil
	}

	_, rete, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ones, bits := rete.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("sono supportate solo reti IPv4")
	}
	if ones < 22 {
		return nil, fmt.Errorf("rete troppo ampia (/%d): il massimo e' /22, "+
			"pari a 1022 indirizzi", ones)
	}

	base := binary.BigEndian.Uint32(rete.IP.To4())
	maschera := binary.BigEndian.Uint32(net.IP(rete.Mask).To4())
	ultimo := base | ^maschera

	// Su /31 e /32 non esistono indirizzo di rete e broadcast nel
	// senso consueto: si restituisce l'intero intervallo.
	primo := base
	fine := ultimo
	if ones < 31 {
		primo = base + 1
		fine = ultimo - 1
	}

	var indirizzi []net.IP
	for v := primo; v <= fine; v++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, v)
		indirizzi = append(indirizzi, ip)
		if v == ^uint32(0) {
			break // evita l'overflow sull'ultimo indirizzo possibile
		}
	}

	return indirizzi, nil
}

// stampaScan produce l'elenco degli host attivi e il riepilogo.
func stampaScan(esiti []EsitoHost, modo modoICMP, tentativi int, durata time.Duration) {
	var vivi, soloTCP, soloICMP, instabili int

	for _, e := range esiti {
		if !e.Vivo() {
			continue
		}
		vivi++

		var canali []string
		if e.RispICMP {
			canali = append(canali, "icmp "+arrotonda(e.RttICMP))
		}
		if e.RispTCP {
			canali = append(canali, fmt.Sprintf("tcp/%d %s",
				e.PortaTCP, arrotonda(e.RttTCP)))
		}

		riga := fmt.Sprintf("%-16s attivo   %s", e.IP, strings.Join(canali, ", "))

		var note []string

		switch {
		case e.RispICMP && e.RispTCP:
			// nessuna annotazione: risponde su entrambi i canali
		case e.RispTCP:
			soloTCP++
			if modo != icmpAssente {
				note = append(note, "ICMP senza risposta")
			}
		case e.RispICMP:
			soloICMP++
			note = append(note, "nessuna porta sonda raggiungibile")
		}

		// Una risposta arrivata solo dopo il primo tentativo indica
		// perdita di pacchetti sul percorso, non un host lento.
		if e.Tentativo > 1 {
			instabili++
			note = append(note, fmt.Sprintf("risposta al %d° tentativo", e.Tentativo))
		}

		if len(note) > 0 {
			riga += "   [" + strings.Join(note, ", ") + "]"
		}

		fmt.Println(riga)
	}

	if vivi == 0 {
		fmt.Println("nessun host attivo rilevato")
	}

	fmt.Printf("\n%d host attivi su %d indirizzi  (in %s)\n",
		vivi, len(esiti), durata.Round(time.Millisecond))

	if modo != icmpAssente && soloTCP > 0 {
		fmt.Printf("\nnota: %d host rispondono su TCP ma non a ICMP. E' il\n", soloTCP)
		fmt.Println("comportamento tipico dei sistemi con il ping bloccato da policy:")
		fmt.Println("una verifica basata sul solo ICMP li darebbe per spenti.")
	}
	if soloICMP > 0 {
		fmt.Printf("\nnota: %d host rispondono al ping ma nessuna delle porte sonda\n", soloICMP)
		fmt.Println("e' raggiungibile. Per sapere cosa espongono conviene interrogarli")
		fmt.Println("singolarmente con un profilo di porte.")
	}
	if instabili > 0 {
		fmt.Printf("\nnota: %d host hanno risposto solo dopo il primo tentativo.\n", instabili)
		fmt.Println("La perdita di pacchetti indica un collegamento poco affidabile:")
		fmt.Println("tipicamente wifi con segnale debole o apparati sotto carico.")
	}
}
