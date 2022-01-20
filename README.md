# Suricata IDS

~~**Surikata** (také **hrabačka surikata**, **promyka surikata**, *Suricata suricatta*) je denní pospolitě žijící promykovitášelma~~

## IDS

- **I**ntrusion **D**etection **S**ystem
- systém moniturující síťový provoz
- detekuje neobvyklé/podezřelé aktivity, které by mohly vést k naručení bezpečnosti počítačové sítě nebo operačního systému
- nemonitoruje pouze finální pokusy o prolomení bezpečností, ale detekuje i akce, které jim předchází
- IDS je pasivní systém (narozdíl od IPS - **I**ntrusion **P**revention **S**ystem) → po detekci neobvyklé aktivity vygeneruje alert, provede zápis do logu a upozorní admina
- senzor = prvek, který obsahuje mechanismy pro detekci škodlivých kódů

### HIDS

- **H**ost **I**ntrusion **D**etection **S**ystem
- beží na jednotlivých zařízeních v síti
- zkoumá příchozí a odchozí pakety tohoto zařízení

### NIDS

- **N**etwork **I**ntrusion **D**etection **S**ystem
- umístěn na strategických místech
- monitoruje veškerý provoz v síti

### Detekce

   #### Signature-based

   - porovnává provoz s přednastavených souborem pravidel (signatures)

   #### Anomaly-base

   - porovnává provoz se stanoveným základem (ten vzniká ohodnocením běžného síťového provozu)

## IPS

- **I**ntrusion **P**revention **S**ystem
- systém monitorující síťový provoz
- jedná se o aktivní systém
- IPS narozdíl od IDS může aktivně zabraňovat a blokovat detekované průniky → vyšle hlášení, zahodí škodlivé pakety nebo obnové připojení

### HIPS

- **H**ost **I**ntrusion **P**revention **S**ystem
- podobné jako u HIDS

### NIPS

- **N**etwork **I**ntrusion **P**revention **S**ystem
- podobné jako u NIDS

## Suricata

- open source systém
- vyvíjen OISF (**O**pen **I**nformation **S**ecurity **F**oundation)
- dostupný na Linuxu, macOS a Windows
- první betaverze → prosinec 2009
- verze 1.0.0 → červenec 2010
- nejaktuálnější (stable) verze 6.0.4 → listopad 2021
- kombinuje IDS, IPS a NSM (**N**etwork **S**ecurity **M**onitoring)
- je schopen rychle identifikovat, zastavit a posoudit i nejsofistikovanější útoky
- multi-threaded → zvýšení schopnosti přijetí paketu, nedojde k ignorovaní paketu kvůli omezené kapacitě → využívaní u vysokorychlostních sítí → vyšší nároky na procesor

### Suricata Rules

- signatures
- nejčastěji jsou používané již existující rulesety (soubory pravidel), uživatel si je tedy nepíše sám
- příklad pravidla:

```Bash
drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; pcre:"/NICK .*USA.*[0-9]{3,}/i"; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)
```

- pravidla se skládají z:

   **Akce (action)**

   - z příkladu → `drop` - zahodí paket a vygeneruje alert
   - další jsou → `pass` - zastavení další inspekce paketu; `alert` - vygeneruje alert; `reject`

   **Hlavičky (header)**

   - osahuje **protokol**
      - z př. → `tcp`
      - říká kterého protokolu se to týka
      - lze vybírat ze čtyř protokolů → `tcp`, `udp`, `icmp` a `ip`
   - **source a destination IP adresy**
      - z př. → `$HOME_NET`; `$EXTERNAL_NET`
      - první část je source a druhá je destination
      - můžeme použít IP adresy i rozsahy (ranges)
   - **souce a destiantion porty**
      - z př. → `any`; `any`
      - první část je source a druhá je destination
   - **směr**
      - z př. → `->`
      - směr, jakým se má signature shodovat
      - nejčastěji jde šipka z leva do prava, je ale i možné, aby šla oběma směry `<>`
      - šipka nemůže jít z prava do leva (`<-`)

   **Možností (rule options)**

   - z př. → `(msg:”ET TROJAN Likely Bot Nick in IRC (USA +..)”; flow:established,to_server; flowbits:isset,is_proto_irc; content:”NICK “; pcre:”/NICK .USA.0-9{3,}/i”; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)`
   - co se má stát

