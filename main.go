// netools - verifica dello stato delle porte TCP di un host
//            e scoperta degli host attivi su una rete
//
// Copyright (C) 2026 Silvestro Scuderi
//
// Questo programma e' software libero: puoi redistribuirlo e/o modificarlo
// secondo i termini della GNU General Public License come pubblicata dalla
// Free Software Foundation, either version 3 della Licenza, o (a tua scelta)
// una versione successiva.
//
// Questo programma e' distribuito nella speranza che sia utile, ma SENZA
// ALCUNA GARANZIA; senza neppure la garanzia implicita di COMMERCIABILITA'
// o IDONEITA' PER UN PARTICOLARE SCOPO. Vedi la GNU General Public License
// per maggiori dettagli.
//
// Dovresti aver ricevuto una copia della GNU General Public License insieme
// a questo programma. In caso contrario, vedi <https://www.gnu.org/licenses/>.

package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	nomeProgramma = "netools"
	versione      = "0.5"
	autore        = "Silvestro Scuderi"
	licenza       = "GPLv3"

	// Verifica delle porte di un host: ogni porta impegna un solo
	// descrittore, quindi il valore puo' essere generoso.
	concorrenzaPorteDefault = 50

	// Scansione di rete: ogni host in prova impegna tanti descrittori
	// quante sono le porte sonda, e valori alti saturano facilmente
	// gli apparati di rete domestici. Il default e' piu' prudente.
	concorrenzaScanDefault = 20
)

// Stato rappresenta l'esito del test su una singola porta.
type Stato int

const (
	Aperta Stato = iota
	Chiusa
	Filtrata
	Errore
)

func (s Stato) String() string {
	switch s {
	case Aperta:
		return "APERTA"
	case Chiusa:
		return "CHIUSA"
	case Filtrata:
		return "FILTRATA"
	default:
		return "ERRORE"
	}
}

// Risultato del test su una porta.
type Risultato struct {
	Porta    int
	Stato    Stato
	Durata   time.Duration
	Dettagli string
}

// profili raccoglie gli elenchi di porte richiamabili per nome.
var profili = map[string][]int{
	"standard": {
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
		389, 443, 445, 636, 993, 995, 1433, 1521, 3306,
		3389, 5432, 5900, 8080, 8443,
	},
	"storage": {
		22,    // SSH / CLI switch e array
		80,    // management HTTP
		111,   // portmapper (NFS)
		135,   // RPC endpoint mapper
		139,   // NetBIOS session
		427,   // SLP (discovery array)
		443,   // management HTTPS
		445,   // SMB
		2049,  // NFS
		3009,  // Data Domain replication
		3260,  // iSCSI target
		5988,  // CIM/SMI-S in chiaro
		5989,  // CIM/SMI-S su TLS
		8000,  // management alternativa
		8080,  // OneFS / interfacce API
		8443,  // management HTTPS alternativa
		10000, // NDMP (backup)
	},
	"web": {
		80, 443, 591, 3000, 4200, 5000, 7001, 8000, 8008,
		8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443,
	},
}

// Parametri regolabili da riga di comando.
var (
	optTimeout     = flag.Duration("t", 2*time.Second, "timeout per singola prova")
	optConcorrenza = flag.Int("c", 0, "prove contemporanee (0 = valore predefinito)")
	optTentativi   = flag.Int("r", 2, "tentativi ICMP per host (solo con scan)")
	optSoloAperte  = flag.Bool("a", false, "mostra soltanto le porte aperte")
	optVersione    = flag.Bool("v", false, "mostra la versione ed esce")
)

func main() {
	flag.Usage = stampaHelp
	flag.Parse()

	if *optVersione {
		fmt.Printf("%s %s - %s - licenza %s\n",
			nomeProgramma, versione, autore, licenza)
		os.Exit(0)
	}

	// Nessun argomento posizionale: mostra l'help.
	if flag.NArg() < 1 {
		stampaHelp()
		os.Exit(0)
	}

	if *optConcorrenza < 0 {
		fmt.Fprintln(os.Stderr, "il valore di -c non puo' essere negativo")
		os.Exit(2)
	}

	// Sottocomando "scan": scoperta degli host attivi su una rete.
	if strings.ToLower(flag.Arg(0)) == "scan" {
		os.Exit(avviaScan())
	}

	os.Exit(eseguiPorte())
}

// avviaScan prepara i parametri del sottocomando scan e lo esegue.
func avviaScan() int {
	if flag.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "manca la rete da scandire")
		fmt.Fprintf(os.Stderr, "esempio: %s scan 192.168.1.0/24\n\n", nomeProgramma)
		stampaHelp()
		return 2
	}

	concorrenza := *optConcorrenza
	if concorrenza == 0 {
		concorrenza = concorrenzaScanDefault
	}

	tentativi := *optTentativi
	if tentativi < 1 {
		tentativi = 1
	}

	return eseguiScan(flag.Arg(1), *optTimeout, concorrenza, tentativi)
}

// eseguiPorte gestisce la verifica delle porte di un singolo host.
func eseguiPorte() int {
	host := flag.Arg(0)

	// Host senza specifica porte: usa il profilo standard.
	// Gli argomenti dal secondo in poi vengono uniti, cosi' funzionano
	// sia "22,80,443" sia "22 80 443" sia forme miste come
	// "standard 8023-8050 9000".
	spec := "standard"
	if flag.NArg() >= 2 {
		spec = strings.Join(flag.Args()[1:], ",")
	}

	porte, err := parsePorte(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "porte non valide: %v\n\n", err)
		stampaHelp()
		return 2
	}

	// Risoluzione una volta sola: un fallimento DNS non deve
	// travestirsi da porta filtrata.
	ip, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "risoluzione di %s fallita: %v\n", host, err)
		return 1
	}

	concorrenza := *optConcorrenza
	if concorrenza == 0 {
		concorrenza = concorrenzaPorteDefault
	}
	if concorrenza > len(porte) {
		concorrenza = len(porte)
	}

	fmt.Printf("%s %s - scansione di %s (%s)\n",
		nomeProgramma, versione, host, ip.IP)
	fmt.Printf("%d porte, timeout %v, %d connessioni contemporanee\n\n",
		len(porte), *optTimeout, concorrenza)

	inizioTotale := time.Now()
	risultati := scansiona(ip.IP.String(), porte, *optTimeout, concorrenza)
	durataTotale := time.Since(inizioTotale)

	stampaRisultati(risultati, durataTotale)
	return 0
}

// scansiona esegue il test su tutte le porte in parallelo, rispettando
// il limite di connessioni contemporanee, e restituisce i risultati
// nello stesso ordine delle porte ricevute in ingresso.
func scansiona(ip string, porte []int, timeout time.Duration, concorrenza int) []Risultato {
	// Slice preallocato: ogni goroutine scrive nella propria cella,
	// quindi non serve alcun lock. L'ordine e' garantito dall'indice.
	risultati := make([]Risultato, len(porte))

	// Canale bufferizzato usato come semaforo: non trasporta dati,
	// conta i permessi. Quando il buffer e' pieno, chi vuole entrare
	// resta in attesa finche' qualcuno non esce.
	semaforo := make(chan struct{}, concorrenza)

	var wg sync.WaitGroup
	var completate int64

	// Progressione su stderr, cosi' l'output dei risultati su stdout
	// resta pulito e puo' essere rediretto senza sporcature.
	fineProgresso := make(chan struct{})
	progressoTerminato := make(chan struct{})
	mostraProgresso := len(porte) > 20

	if mostraProgresso {
		go func() {
			defer close(progressoTerminato)
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					fatte := atomic.LoadInt64(&completate)
					fmt.Fprintf(os.Stderr, "\rverificate %d/%d porte...", fatte, len(porte))
				case <-fineProgresso:
					fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 40))
					return
				}
			}
		}()
	}

	for i, p := range porte {
		wg.Add(1)

		go func(indice, porta int) {
			defer wg.Done()

			semaforo <- struct{}{}        // acquisisce il permesso
			defer func() { <-semaforo }() // lo rilascia all'uscita

			risultati[indice] = testPorta(ip, porta, timeout)
			atomic.AddInt64(&completate, 1)
		}(i, p)
	}

	wg.Wait()

	if mostraProgresso {
		close(fineProgresso)
		// Attesa esplicita che la riga di progresso sia stata ripulita,
		// cosi' i risultati non escono mescolati ai residui.
		<-progressoTerminato
	}

	return risultati
}

// stampaRisultati produce l'elenco e il riepilogo finale.
func stampaRisultati(risultati []Risultato, durataTotale time.Duration) {
	var aperte, chiuse, filtrate, errori int
	var mostrate int

	for _, r := range risultati {
		switch r.Stato {
		case Aperta:
			aperte++
		case Chiusa:
			chiuse++
		case Filtrata:
			filtrate++
		default:
			errori++
		}

		if *optSoloAperte && r.Stato != Aperta {
			continue
		}

		riga := fmt.Sprintf("%5d/tcp  %-9s %8s  %-12s",
			r.Porta, r.Stato, arrotonda(r.Durata), nomeServizio(r.Porta))
		if r.Dettagli != "" {
			riga += " [" + r.Dettagli + "]"
		}
		fmt.Println(strings.TrimRight(riga, " "))
		mostrate++
	}

	if *optSoloAperte && mostrate == 0 {
		fmt.Println("nessuna porta aperta")
	}

	fmt.Printf("\n%d aperte, %d chiuse, %d filtrate", aperte, chiuse, filtrate)
	if errori > 0 {
		fmt.Printf(", %d errori", errori)
	}
	fmt.Printf("  (in %s)\n", durataTotale.Round(time.Millisecond))

	// Il confronto fra risposte esplicite e silenzio e' l'indizio
	// piu' utile sulla presenza di un filtro selettivo.
	if filtrate > 0 && chiuse > 0 {
		fmt.Println("\nnota: la presenza di porte che rispondono con RST accanto ad altre")
		fmt.Println("che restano in silenzio indica un filtro selettivo lungo il percorso.")
	}
}

// testPorta apre una connessione TCP completa e classifica l'esito.
// Le funzioni di riconoscimento degli errori sono definite in
// errori_unix.go ed errori_windows.go: il compilatore include solo
// quella adatta al sistema di destinazione.
func testPorta(ip string, porta int, timeout time.Duration) Risultato {
	indirizzo := net.JoinHostPort(ip, strconv.Itoa(porta))

	inizio := time.Now()
	conn, err := net.DialTimeout("tcp", indirizzo, timeout)
	durata := time.Since(inizio)

	// SYN-ACK ricevuto: la porta ascolta.
	if err == nil {
		conn.Close()
		return Risultato{Porta: porta, Stato: Aperta, Durata: durata}
	}

	// RST ricevuto: rifiuto esplicito. Host raggiungibile,
	// nessun servizio in ascolto (oppure firewall in reject).
	if rifiutoEsplicito(err) {
		return Risultato{Porta: porta, Stato: Chiusa, Durata: durata}
	}

	// ICMP unreachable dal router.
	if hostIrraggiungibile(err) {
		return Risultato{Porta: porta, Stato: Filtrata, Durata: durata,
			Dettagli: "host unreachable"}
	}
	if reteIrraggiungibile(err) {
		return Risultato{Porta: porta, Stato: Filtrata, Durata: durata,
			Dettagli: "network unreachable"}
	}

	// Esaurimento dei descrittori: limite locale, non diagnosi di rete.
	if descrittoriEsauriti(err) {
		return Risultato{Porta: porta, Stato: Errore, Durata: durata,
			Dettagli: "descrittori esauriti: riduci il valore di -c"}
	}

	// Silenzio fino allo scadere del timeout: pacchetti scartati.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return Risultato{Porta: porta, Stato: Filtrata, Durata: durata,
			Dettagli: "nessuna risposta"}
	}

	return Risultato{Porta: porta, Stato: Errore, Durata: durata,
		Dettagli: err.Error()}
}

// parsePorte accetta profili, porte singole, elenchi e intervalli,
// anche combinati fra loro separandoli con la virgola.
func parsePorte(spec string) ([]int, error) {
	visti := make(map[int]bool)
	var porte []int

	aggiungi := func(p int) error {
		if p < 1 || p > 65535 {
			return fmt.Errorf("porta %d fuori intervallo 1-65535", p)
		}
		if !visti[p] {
			visti[p] = true
			porte = append(porte, p)
		}
		return nil
	}

	for _, pezzo := range strings.Split(spec, ",") {
		pezzo = strings.ToLower(strings.TrimSpace(pezzo))
		if pezzo == "" {
			continue
		}

		// Profilo richiamato per nome.
		if elenco, ok := profili[pezzo]; ok {
			for _, p := range elenco {
				if err := aggiungi(p); err != nil {
					return nil, err
				}
			}
			continue
		}

		// Intervallo con trattino.
		if strings.Contains(pezzo, "-") {
			estremi := strings.SplitN(pezzo, "-", 2)
			da, err := strconv.Atoi(strings.TrimSpace(estremi[0]))
			if err != nil {
				return nil, fmt.Errorf("valore non numerico in %q", pezzo)
			}
			a, err := strconv.Atoi(strings.TrimSpace(estremi[1]))
			if err != nil {
				return nil, fmt.Errorf("valore non numerico in %q", pezzo)
			}
			if da > a {
				return nil, fmt.Errorf("intervallo invertito in %q", pezzo)
			}
			for p := da; p <= a; p++ {
				if err := aggiungi(p); err != nil {
					return nil, err
				}
			}
			continue
		}

		// Porta singola.
		p, err := strconv.Atoi(pezzo)
		if err != nil {
			return nil, fmt.Errorf("%q non e' ne' un profilo ne' un numero", pezzo)
		}
		if err := aggiungi(p); err != nil {
			return nil, err
		}
	}

	if len(porte) == 0 {
		return nil, errors.New("nessuna porta specificata")
	}

	sort.Ints(porte)
	return porte, nil
}

// nomeServizio restituisce un'etichetta indicativa per le porte note.
func nomeServizio(p int) string {
	nomi := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
		80: "http", 110: "pop3", 111: "portmapper", 135: "msrpc",
		139: "netbios", 143: "imap", 389: "ldap", 427: "slp",
		443: "https", 445: "smb", 636: "ldaps", 993: "imaps",
		995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
		3009: "datadomain", 3260: "iscsi", 3306: "mysql",
		3389: "rdp", 5432: "postgres", 5900: "vnc",
		5988: "cim", 5989: "cim-tls", 8000: "http-mgmt",
		8080: "http-alt", 8443: "https-alt", 9000: "http-alt",
		9090: "http-mgmt", 10000: "ndmp",
	}
	return nomi[p]
}

// arrotonda riduce la precisione per un output leggibile.
func arrotonda(d time.Duration) string {
	if d < time.Millisecond {
		return d.Round(10 * time.Microsecond).String()
	}
	return d.Round(time.Millisecond).String()
}

func stampaHelp() {
	fmt.Printf("%s %s - verifica porte TCP e scoperta host di rete\n",
		nomeProgramma, versione)
	fmt.Printf("Copyright (C) 2026 %s - licenza %s\n", autore, licenza)
	fmt.Println("Software libero: sei libero di modificarlo e ridistribuirlo.")
	fmt.Println("NESSUNA GARANZIA, nei limiti consentiti dalla legge.")
	fmt.Println()
	fmt.Println("SINTASSI")
	fmt.Printf("  %s [opzioni] <host> [porte]     verifica le porte di un host\n", nomeProgramma)
	fmt.Printf("  %s [opzioni] scan <rete>        elenca gli host attivi\n", nomeProgramma)
	fmt.Println()
	fmt.Println("  <host>   indirizzo IP o nome risolvibile")
	fmt.Println("  [porte]  se omesso viene usato il profilo 'standard'")
	fmt.Println("  <rete>   notazione CIDR, da /22 a /32 (es. 192.168.1.0/24)")
	fmt.Println()
	fmt.Println("OPZIONI")
	fmt.Println("  -t durata   timeout per singola prova          (default 2s)")
	fmt.Println("  -c numero   prove contemporanee                (50 porte, 20 scan)")
	fmt.Println("  -r numero   tentativi ICMP per host            (default 2, solo scan)")
	fmt.Println("  -a          mostra soltanto le porte aperte")
	fmt.Println("  -v          mostra la versione")
	fmt.Println()
	fmt.Println("  Le opzioni vanno indicate prima dell'host o del sottocomando.")
	fmt.Println()
	fmt.Println("SPECIFICA PORTE")
	fmt.Println("  profilo       standard | storage | web")
	fmt.Println("  porta singola 8023")
	fmt.Println("  elenco        22,80,443   oppure   22 80 443")
	fmt.Println("  intervallo    8023-8050")
	fmt.Println("  combinazione  standard,8023-8050")
	fmt.Println()
	fmt.Println("PROFILI")
	fmt.Printf("  standard  %2d porte  servizi di rete piu' diffusi\n", len(profili["standard"]))
	fmt.Printf("  storage   %2d porte  management array, SAN/NAS, backup\n", len(profili["storage"]))
	fmt.Printf("  web       %2d porte  interfacce HTTP/HTTPS su porte alternative\n", len(profili["web"]))
	fmt.Println()
	fmt.Println("ESEMPI")
	fmt.Printf("  %s 10.0.0.5                    profilo standard\n", nomeProgramma)
	fmt.Printf("  %s 10.0.0.5 storage            profilo storage\n", nomeProgramma)
	fmt.Printf("  %s 10.0.0.5 8023-8050          intervallo\n", nomeProgramma)
	fmt.Printf("  %s -a -c 100 10.0.0.5 1-1024   scansione ampia\n", nomeProgramma)
	fmt.Printf("  %s scan 192.168.1.0/24         host attivi sulla rete\n", nomeProgramma)
	fmt.Printf("  %s -t 1s -r 3 scan 10.0.0.0/24 rete con collegamenti instabili\n", nomeProgramma)
	fmt.Println()
	fmt.Println("STATI DELLE PORTE")
	fmt.Println("  APERTA    handshake completato, un servizio ascolta")
	fmt.Println("  CHIUSA    RST ricevuto: host raggiungibile, nessun servizio")
	fmt.Println("  FILTRATA  nessuna risposta: pacchetti scartati da un firewall")
	fmt.Println()
	fmt.Println("SCOPERTA HOST")
	fmt.Println("  Vengono usate entrambe le sonde, ICMP e TCP: i due canali possono")
	fmt.Println("  essere filtrati in modo indipendente, e un host che ignora il ping")
	fmt.Println("  puo' comunque rispondere su una porta. Se il socket ICMP non e'")
	fmt.Println("  disponibile viene usata la sola sonda TCP, e cio' viene indicato")
	fmt.Println("  nell'intestazione.")
	fmt.Println()
	fmt.Println("  ICMP non prevede ritrasmissione: gli indirizzi silenziosi vengono")
	fmt.Println("  ritentati per non dare per spento un host che ha semplicemente")
	fmt.Println("  perso un pacchetto. Su reti con molti collegamenti wifi conviene")
	fmt.Println("  alzare -r a 3.")
	fmt.Println()
	fmt.Println("NOTE")
	fmt.Println("  Solo TCP. I servizi UDP (snmp, ipmi, syslog) non vengono rilevati.")
	fmt.Println("  La prima scansione di una rete e' sempre la piu' lenta: la cache ARP")
	fmt.Println("  e' vuota e ogni indirizzo richiede una risoluzione preliminare.")
	fmt.Println("  Valori alti di -c saturano gli apparati di rete e producono falsi")
	fmt.Println("  negativi: se i risultati variano fra esecuzioni successive, il")
	fmt.Println("  valore e' troppo alto.")
	fmt.Println("  La scoperta di host su una rete e' a tutti gli effetti un'attivita'")
	fmt.Println("  di ricognizione: su infrastrutture non proprie va concordata prima.")
}
