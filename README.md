# netools

Strumento a riga di comando per due domande che si pongono spesso insieme: **quali host sono attivi su una rete** e **quali porte espone un host**.

Binario singolo senza dipendenze, compilabile per Linux, macOS, Windows e FreeBSD a partire dallo stesso sorgente.

## A cosa serve

I comandi tradizionali dicono se qualcosa risponde. `netools` dice **come** risponde, e da lì si ricava molto di più.

Sulle porte di un host:

| Stato | Cosa è successo | Interpretazione |
|---|---|---|
| `APERTA` | handshake completato | un servizio è in ascolto |
| `CHIUSA` | ricevuto RST | l'host è raggiungibile, nessun servizio su quella porta |
| `FILTRATA` | nessuna risposta entro il timeout | i pacchetti vengono scartati in silenzio |

La differenza fra `CHIUSA` e `FILTRATA` è l'informazione più utile: un host che risponde con RST è raggiungibile e sta dichiarando che lì non ascolta nessuno, mentre il silenzio indica un firewall in *drop*.

Sulla scoperta degli host, la logica è la stessa applicata a due canali distinti: ICMP e TCP possono essere filtrati in modo indipendente, e sapere su quale dei due un host risponde dice qualcosa sulla sua configurazione.

## Leggere i risultati

### Porte di un host

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

Venti porte rispondono in 174ms e tre spariscono nel nulla. Se il filtro fosse sull'host si applicherebbe con criteri uniformi; il fatto che a tacere siano esattamente 135, 139 e 445 — le porte Windows — indica un blocco **a monte**, tipicamente deciso dal provider o da un firewall perimetrale.

Al contrario, un host che restituisce solo `APERTA` e `FILTRATA` senza nessun RST ha una postura difensiva completa: tutto ciò che non è esplicitamente pubblicato viene scartato.

Come regola pratica: tempo di rete = risposta esplicita, timeout pieno = silenzio.

### Host su una rete

```
192.168.1.1      attivo   icmp 1ms, tcp/80 4ms
192.168.1.60     attivo   icmp 620µs, tcp/3389 2ms
192.168.1.101    attivo   icmp 40ms   [nessuna porta sonda raggiungibile]
192.168.1.130    attivo   icmp 22ms   [risposta al 2° tentativo]
192.168.1.155    attivo   tcp/80 131ms   [ICMP senza risposta]
```

Tre situazioni diverse, tutte utili:

**Risposta su entrambi i canali** — l'host è raggiungibile e almeno una porta comune è esposta.

**Solo ICMP** — l'host risponde al ping ma nessuna delle porte sonda è raggiungibile. Tipico degli apparati che espongono la gestione su porte non convenzionali; per sapere cosa offrono conviene interrogarli con un profilo di porte.

**Solo TCP** — l'host ha il ping bloccato da policy, comportamento comune sui sistemi in dominio Windows. Una verifica basata sul solo `ping` lo darebbe per spento.

L'annotazione `risposta al 2° tentativo` segnala un pacchetto perso al primo giro: indica un collegamento poco affidabile, tipicamente wifi con segnale debole, e su una rete che non si conosce è un'informazione operativa più che un dettaglio.

## Uso

```
netools [opzioni] <host> [porte]     verifica le porte di un host
netools [opzioni] scan <rete>        elenca gli host attivi
```

Senza argomenti viene mostrata la guida.

### Specifica delle porte

Se le porte sono omesse viene usato il profilo `standard`.

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

### Scansione di rete

```
netools scan 192.168.1.0/24         una rete /24
netools scan 10.0.0.0/22            il massimo consentito, 1022 indirizzi
netools -t 1s -r 3 scan 10.0.0.0/24 rete con collegamenti instabili
```

Sono accettate reti da /22 a /32. Il limite serve a evitare che una svista sulla maschera trasformi una verifica in una scansione da decine di migliaia di indirizzi.

### Opzioni

| Opzione | Default | Descrizione |
|---|---|---|
| `-t` | `2s` | timeout per singola prova |
| `-c` | 50 porte, 20 scan | prove contemporanee |
| `-r` | `2` | tentativi ICMP per host (solo con `scan`) |
| `-a` | | mostra soltanto le porte aperte |
| `-v` | | mostra la versione |

Le opzioni vanno indicate **prima** dell'host o del sottocomando.

```
netools -t 500ms 10.0.0.5 storage      timeout ridotto, adatto alla LAN
netools -a -c 100 10.0.0.5 1-1024      scansione ampia, solo le aperte
netools -t 1s -c 10 scan 10.0.0.0/24   scansione prudente
```

### Profili

| Nome | Porte | Contenuto |
|---|---|---|
| `standard` | 25 | servizi di rete più diffusi |
| `storage` | 17 | management di array, SAN/NAS, backup |
| `web` | 17 | interfacce HTTP/HTTPS su porte alternative |

## Installazione

I binari già compilati per tutte le piattaforme supportate si trovano nella sezione [Releases](https://github.com/silfox70/netools/releases).

Con Go installato:

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
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o netools-linux-arm64
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o netools-windows-amd64.exe
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o netools-darwin-arm64
CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -ldflags="-s -w" -o netools-freebsd-amd64
```

Su macOS un binario scaricato viene messo in quarantena da Gatekeeper. Si sblocca con:

```
xattr -d com.apple.quarantine netools-darwin-arm64
```

## Funzionamento

### Verifica delle porte

Il test usa una `connect()` TCP completa, non un SYN scan: non servono privilegi di amministratore e il programma può girare come utente normale.

I codici di errore restituiti dallo stack di rete non coincidono fra sistemi POSIX e Windows — un RST arriva come `ECONNREFUSED` sui primi e come `WSAECONNREFUSED` sul secondo. La mappatura è isolata in `errori_unix.go` ed `errori_windows.go`, selezionati automaticamente dal compilatore tramite build constraint.

Le porte vengono verificate in parallelo con un limite di connessioni contemporanee: il tempo totale è quello della porta più lenta, non la somma di tutte. Un profilo da 25 porte con tre filtrate passa da circa 10 secondi a poco più del timeout impostato.

### Scoperta degli host

Vengono usate entrambe le sonde. Per ICMP il programma tenta prima il raw socket e, se non è disponibile, ripiega sul socket ICMP non privilegiato: su macOS e su molte distribuzioni Linux questo consente il ping anche senza privilegi. Se nessuno dei due si apre, la scansione prosegue con la sola sonda TCP e la limitazione viene dichiarata nell'intestazione.

La sonda TCP considera prova di vita sia una connessione accettata sia un RST: in entrambi i casi qualcuno ha risposto.

ICMP non prevede ritrasmissione, quindi un pacchetto perso equivarrebbe a un host dichiarato spento. Gli indirizzi silenziosi vengono ritentati, e siccome ogni giro interroga solo chi non ha ancora risposto, il costo dei tentativi successivi è proporzionale ai silenziosi e non al totale della rete.

## Taratura

Su una rete locale il timeout predefinito di 2 secondi è largamente sovradimensionato: `-t 500ms` sulle porte e `-t 1s` sulla scansione danno gli stessi risultati in una frazione del tempo.

La **prima scansione di una rete è sempre la più lenta**, perché la cache ARP è vuota e ogni indirizzo richiede una risoluzione preliminare. Su una /24 la differenza fra prima e seconda esecuzione può essere di un fattore cinque. Per un inventario affidabile conviene lanciarla due volte e usare il secondo risultato.

Valori alti di `-c` **saturano gli apparati di rete e producono falsi negativi**. Se i risultati variano fra esecuzioni successive, il valore è troppo alto: su una rete domestica `-c 10` è già sufficiente. Ogni host in prova impegna tanti descrittori quante sono le porte sonda, quindi vale la pena controllare `ulimit -n` prima di alzare il valore.

## Limitazioni

**Solo TCP.** I servizi UDP (SNMP, IPMI, syslog, NTP) non vengono rilevati. Su UDP l'assenza di risposta è il comportamento normale di un servizio funzionante, quindi la classificazione richiederebbe una logica diversa.

**Solo IPv4.**

**Lo stato `CHIUSA` non identifica chi ha risposto.** Un RST può provenire dall'host oppure da un firewall configurato in *reject* anziché in *drop*. Ciò che il test stabilisce con certezza è la differenza fra rifiuto esplicito e silenzio.

**La connessione viene completata**, quindi lascia traccia nei log del sistema di destinazione.

**La scansione di rete è un'attività di ricognizione.** Su infrastrutture non proprie va concordata in anticipo: valori aggressivi di `-c` fanno scattare gli IDS, e in ambienti sorvegliati la conseguenza è un blocco automatico.

## Licenza

GPLv3 — vedi il file [LICENSE](LICENSE).

Copyright (C) 2026 Silvestro Scuderi
