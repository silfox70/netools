# netools

Verifica lo stato delle porte TCP di un host e distingue una porta chiusa da una filtrata da un firewall.

Binario singolo senza dipendenze, compilabile per Linux, macOS e Windows a partire dallo stesso sorgente.

## A cosa serve

I comandi tradizionali dicono se una porta risponde. `netools` dice **come** risponde, e da lì si ricava se c'è un filtro lungo il percorso:

| Stato | Cosa è successo | Interpretazione |
|---|---|---|
| `APERTA` | handshake completato | un servizio è in ascolto |
| `CHIUSA` | ricevuto RST | l'host è raggiungibile, nessun servizio su quella porta |
| `FILTRATA` | nessuna risposta entro il timeout | i pacchetti vengono scartati in silenzio |

La differenza fra `CHIUSA` e `FILTRATA` è l'informazione più utile: un host che risponde con RST è raggiungibile e sta dichiarando che lì non ascolta nessuno, mentre il silenzio indica un firewall in *drop*.

## Leggere i risultati

I tempi contano quanto gli stati.

```
   21/tcp  CHIUSA       174ms  ftp
   22/tcp  APERTA       173ms  ssh
   80/tcp  APERTA       172ms  http
  135/tcp  FILTRATA    2.001s  msrpc        [nessuna risposta]
  139/tcp  FILTRATA    2.001s  netbios      [nessuna risposta]
  443/tcp  CHIUSA       176ms  https
  445/tcp  FILTRATA     500ms  smb          [nessuna risposta]
```

Venti porte rispondono in 174ms e tre spariscono nel nulla: se il filtro fosse sull'host, si applicherebbe con criteri uniformi. Il fatto che a tacere siano esattamente 135, 139 e 445 — le porte Windows — indica un blocco **a monte**, tipicamente deciso dal provider o da un firewall perimetrale.

Al contrario, un host che restituisce solo `APERTA` e `FILTRATA` senza nessun RST ha una postura difensiva completa: tutto ciò che non è esplicitamente pubblicato viene scartato.

Come regola pratica: tempo di rete = risposta esplicita, timeout pieno = silenzio.

## Uso

```
netools [opzioni] <host> [porte]
```

Se le porte sono omesse viene usato il profilo `standard`.

### Specifica delle porte

```
netools 10.0.0.5                    profilo standard
netools 10.0.0.5 storage            profilo storage
netools 10.0.0.5 8023               porta singola
netools 10.0.0.5 22,80,443          elenco
netools 10.0.0.5 22 80 443          elenco separato da spazi
netools 10.0.0.5 8023-8050          intervallo
netools 10.0.0.5 standard,8023-8050 profilo più intervallo
```

Le porte duplicate vengono unificate e l'output è sempre ordinato.

### Opzioni

| Opzione | Default | Descrizione |
|---|---|---|
| `-t` | `2s` | timeout per singola porta |
| `-c` | `50` | connessioni contemporanee |
| `-a` | | mostra soltanto le porte aperte |
| `-v` | | mostra la versione |

Le opzioni vanno indicate **prima** dell'host.

```
netools -t 500ms 10.0.0.5 storage      timeout ridotto, adatto alla LAN
netools -a -c 100 10.0.0.5 1-1024      scansione ampia, solo le aperte
```

In LAN un timeout di `500ms` è ampiamente sufficiente e riduce di molto i tempi sulle porte filtrate.

### Profili

| Nome | Porte | Contenuto |
|---|---|---|
| `standard` | 25 | servizi di rete più diffusi |
| `storage` | 17 | management di array, SAN/NAS, backup |
| `web` | 17 | interfacce HTTP/HTTPS su porte alternative |

## Installazione

Con Go già installato:

```
go install github.com/silfox70/netools@latest
```

Oppure si compila dal sorgente:

```
git clone https://github.com/silfox70/netools.git
cd netools
go build -o netools
```

### Compilazione per altre piattaforme

Il sorgente è puro Go, quindi la cross-compilazione non richiede alcun toolchain aggiuntivo. `CGO_ENABLED=0` produce un binario statico che non dipende dalla libc del sistema di destinazione.

```
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o netools-linux-amd64
CGO_ENABLED=0 GOOS=linux   GOARCH=386   go build -ldflags="-s -w" -o netools-linux-386
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o netools-linux-arm64
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o netools-windows-amd64.exe
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o netools-darwin-arm64
```

Su macOS, un binario scaricato da internet viene messo in quarantena da Gatekeeper. Si sblocca con:

```
xattr -d com.apple.quarantine netools-darwin-arm64
```

## Funzionamento

Il test usa una `connect()` TCP completa, non un SYN scan: non servono privilegi di amministratore e il programma può girare come utente normale.

I codici di errore restituiti dallo stack di rete non coincidono fra sistemi POSIX e Windows — un RST arriva come `ECONNREFUSED` sui primi e come `WSAECONNREFUSED` sul secondo. La mappatura è isolata in `errori_unix.go` ed `errori_windows.go`, selezionati automaticamente dal compilatore tramite build constraint.

Le porte vengono verificate in parallelo con un limite di connessioni contemporanee: il tempo totale è quello della porta più lenta, non la somma di tutte. Un profilo da 25 porte con tre filtrate passa da circa 10 secondi a poco più del timeout impostato.

## Limitazioni

**Solo TCP.** I servizi UDP (SNMP, IPMI, syslog, NTP) non vengono rilevati. Su UDP l'assenza di risposta è il comportamento normale di un servizio funzionante, quindi la classificazione richiederebbe una logica diversa.

**Lo stato `CHIUSA` non identifica chi ha risposto.** Un RST può provenire dall'host oppure da un firewall configurato in *reject* anziché in *drop*. Ciò che il test stabilisce con certezza è la differenza fra rifiuto esplicito e silenzio.

**La connessione viene completata**, quindi lascia traccia nei log del sistema di destinazione.

**Valori alti di `-c` possono far scattare gli IDS.** Su reti sorvegliate conviene restare sotto la ventina di connessioni contemporanee e concordare preventivamente le verifiche su infrastrutture non proprie.

## Licenza

GPLv3 — vedi il file [LICENSE](LICENSE).

Copyright (C) 2026 Silvestro Scuderi




Aggiunta la scoperta degli host attivi su una rete.

## Novità

**Sottocomando `scan`** — dato un indirizzo di rete in notazione CIDR, elenca gli host attivi:

    netools scan 192.168.1.0/24

Vengono usate due sonde indipendenti, ICMP echo e TCP su porte comuni, perché i due canali possono essere filtrati separatamente: un host con il ping bloccato da policy risponde comunque su una porta, e verrebbe dato per spento da una verifica basata sul solo ICMP. L'output segnala esplicitamente quali host rispondono su un canale soltanto.

Se il socket ICMP non è disponibile viene usata la sola sonda TCP, e la cosa è indicata nell'intestazione anziché passare sotto silenzio. Su macOS e su molte distribuzioni Linux ICMP funziona anche senza privilegi, grazie al socket ICMP non privilegiato.

**Ritentativi ICMP** (opzione `-r`, default 2) — ICMP non prevede ritrasmissione, quindi un pacchetto perso significa host dichiarato spento. Gli indirizzi silenziosi vengono ritentati, e gli host che rispondono solo dopo il primo tentativo sono segnalati come tali: è un indizio di collegamento poco affidabile, tipicamente wifi con segnale debole.

**Correzione della classificazione degli errori su Windows** — i codici Winsock non coincidono con gli errno POSIX. Senza la mappatura corretta una porta chiusa veniva riportata come errore generico, e chi leggeva l'output non aveva modo di accorgersene.

**Porte separate da spazi** oltre che da virgole. In precedenza gli argomenti in eccesso venivano ignorati senza alcun avviso.

## Binari

| File | Sistema | Architettura | Note |
|---|---|---|---|
| `netools-linux-amd64` | Linux | x86-64 | server e desktop |
| `netools-linux-386` | Linux | x86 32 bit | sistemi datati |
| `netools-linux-arm64` | Linux | ARM 64 bit | Raspberry Pi 4/5, VM ARM |
| `netools-linux-armv7` | Linux | ARM 32 bit | Raspberry Pi 2/3 |
| `netools-darwin-arm64` | macOS | Apple Silicon | M1 e successivi |
| `netools-darwin-amd64` | macOS | Intel | |
| `netools-windows-amd64.exe` | Windows | x86-64 | |
| `netools-windows-arm64.exe` | Windows | ARM 64 bit | |
| `netools-freebsd-amd64` | FreeBSD | x86-64 | TrueNAS, pfSense |

Binari statici: non richiedono runtime, librerie di sistema o privilegi di amministratore.

## Uso

Su Linux, macOS e FreeBSD il file va reso eseguibile:

    chmod +x netools-linux-amd64
    ./netools-linux-amd64 10.0.0.5 storage
    ./netools-linux-amd64 scan 10.0.0.0/24

Su macOS un binario scaricato viene messo in quarantena da Gatekeeper e va sbloccato:

    xattr -d com.apple.quarantine netools-darwin-arm64

## Note sulla scansione di rete

La prima scansione di una rete è sempre la più lenta: la cache ARP è vuota e ogni indirizzo richiede una risoluzione preliminare. Su una /24 la differenza fra la prima e la seconda esecuzione può essere di un fattore cinque.

Valori alti di `-c` saturano gli apparati di rete e producono falsi negativi. Se i risultati variano fra esecuzioni successive il valore è troppo alto: su una rete domestica `-c 10` è già sufficiente.

La scoperta di host è a tutti gli effetti un'attività di ricognizione: su infrastrutture non proprie va concordata in anticipo.
