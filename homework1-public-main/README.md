Tema 1 PCOM - Dogaru Laurentiu 323CC

Am rezolvat cerintele:  
    -Procesul de dirijare  
    -Protocolul ARP  
    -Protocolul ICMP

-Initial, se aloca memorie pentru cache-ul ARP, tabela de rutare si pentru
coada de pachete  
-Se verifica field-ul ether_type din header-ul ethernet

Procesul de dirijare:  
  -Daca pachetul are checksum-ul gresit sau are ttl-ul 1 sau 0, este aruncat  
  -Se cauta cea mai buna ruta pentru adresa IP destinatie  
  -Se cauta in cache-ul ARP adresa MAC corespunzatoare adresei IP a urmatorului
  hop  
  -Se decrementeaza ttl-ul si se actualizeaza checksum-ul  
  -Adresa MAC destinatie este cea a urmatorului hop  
  -Campul interfata al pachetului reprezinta interfata pe care acesta trebuie
  trimis catre urmatorul hop, iar adresa interfetei este adresa MAC sursa  

Protocolul ARP:  
 a) Trimiterea request-ului  
  -Daca pe parcursul procesului de dirijare, adresa MAC a urmatorului hop nu
  este in cache, pachetul este pus in coada si se trimite un arp request  
  -Adresa MAC destinatie a requestului este broadcast (FF.FF.FF.FF.FF.FF)  
  -Adresa MAC sursa este cea a interfetei de pe care pachetul trebuie sa
  ajunga la next hop  
  -Campul ether_type din header-ul ethernet este htons(0x806)  
  -Se completeaza campurile din header-ul ARP(formatul adreselor hardware si
  IP, lungimea acestora, iar campul op este setat pe 1, fiind un request)  
  -In header-ul ARP se pun si adresele MAC sursa(a interfetei) si destinatie
  (broadcast) si adresele IP sursa(a interfetei) si destinatie (a urmatorului)
  hop  
 b) Primirea unui reply  
  -Se creeaza un arp_entry care contine adresele MAC si IP ale pachetului si
  se pune in coada  
  -Cat timp sunt pachete in coada a caror adresa a urmatorului hop apare in
  cache-ul ARP, se trimite unul cate unul similar cum am descris in sectiunea
  "Procesul de dirijare"  
 c) Primirea unui ARP request  
  -Daca adresa IP destinatie a pachetului este chiar router-ul, se schimba
  campul "op" din header-ul ARP in 2, se inverseaza adresele IP si MAC din
  header-ul ARP si ethernet, si se trimite pachetul  

Protocolul ICMP:  
  -In cazul in care un pachet cu de tip IPv4 are ttl-ul 1 sau 0 sau nu se 
  gaseste o ruta in tabela de rutare, se va trimite un pachet de timp ICMP cu
  tipul 11, respectiv 3  
  -Pachetul nou creat va avea interfata va avea interfata celui care a fost
  primit si lungimea size(eth_hdr) + size(ip_hdr) + size(icmp_hdr) + 64  
  -Se copiaza antetul ethernet si se inverseaza adresele MAC  
  -Adresa IP sursa e cea a interfetei pe care a venit pachetul, iar cea
  destinatie este cea de la care a venit pachetul  
  -Se copiaza antetul IP, dar se seteaza in antetul IP campul protocol 1, se
   pune un ttl arbitrar 64 si se mareste tot_len - ul cu size(icmp_hdr) + 64  
  -In header-ul ICMP se seteaza campurile type, code si checksum  
  -Daca router-ul primeste pentru adresa lui un pachet de tip "Echo request",
  cu type-ul = 8, atunci trimite un pachet cu type-ul 0, adica un "Echo reply"  
  -In cazul in care se trimite un Echo reply, se copiaza header-ul ICMP din
  request pentru a se pastra octetii 4-7  
