#include "queue.h"
#include "skel.h"

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* ARP table */
struct arp_entry *arp_table;
int arp_table_len;

/* ARP cache */
struct arp_entry *arp_cache;
int arp_cache_size;

queue q;

struct route_table_entry *get_best_route(struct in_addr dest_ip) {
    size_t idx = -1;	

    for (size_t i = 0; i < rtable_len; i++) {
        if ((dest_ip.s_addr & rtable[i].mask) == rtable[i].prefix) {
			if (idx == -1) {
				idx = i;
			} else if (ntohl(rtable[idx].mask) < ntohl(rtable[i].mask)) {
				idx = i;
			}
		}
    }
    if (idx == -1) {
        return NULL;
	} else {
        return &rtable[idx];
	}
}

void icmp(packet *m, int type) {
	packet *to_send = (packet*)malloc(sizeof(packet));

	//PACKET
	to_send->interface = m->interface;
	to_send->len = sizeof(struct ether_header) + sizeof(struct iphdr)
		+ sizeof(struct icmphdr) + 64;

	//ETHER HEADER
	struct ether_header *eth = (struct ether_header*)malloc
		(sizeof(struct ether_header));
	memcpy(eth, m->payload, sizeof(struct ether_header));

	//Swap addresses
	char *aux_mac = (char*)malloc(6 * sizeof(char));
	memcpy(aux_mac, eth->ether_shost, 6 * sizeof(char));
	memcpy(eth->ether_shost, eth->ether_dhost, 6 * sizeof(char));
	memcpy(eth->ether_dhost, aux_mac, 6 * sizeof(char));

	//IPv4 type
	eth->ether_type = htons(0x0800);

	memcpy(to_send->payload, eth, sizeof(struct ether_header));

	//IP HEADER
	struct iphdr *iph = (struct iphdr*)malloc(sizeof(struct iphdr));
	memcpy(iph, m->payload + sizeof(struct ether_header), sizeof(struct iphdr));

	struct in_addr* aux_ip = (struct in_addr*)malloc(sizeof(struct in_addr));
	inet_aton(get_interface_ip(m->interface), aux_ip);
	iph->saddr = aux_ip->s_addr;

	struct iphdr *received_iph = (struct iphdr*)(m->payload 
		+ sizeof(struct ether_header));
	iph->daddr = received_iph->saddr;

	iph->protocol = 1;
	iph->ttl = 64;
	iph->tot_len += sizeof(struct iphdr) + 64;

	memcpy(to_send->payload + sizeof(struct ether_header), iph, 
		sizeof(struct iphdr));

	//ICMP HEADER
	struct icmphdr *icmph = (struct icmphdr*)malloc(sizeof(struct icmphdr));
	if(type == 0) {
		memcpy(icmph, m->payload + sizeof(struct ether_header) 
			+ sizeof(struct iphdr), sizeof(struct icmphdr));
	}
	icmph->type = type;
	icmph->code = 0;
	icmph->checksum = 0;
	icmph->checksum = icmp_checksum((void*)icmph, sizeof(struct icmphdr));

	memcpy(to_send->payload + sizeof(struct ether_header) + 
		sizeof(struct iphdr), icmph, sizeof(struct icmphdr));
	memcpy(iph + sizeof(struct iphdr) + sizeof(struct icmphdr), 
		received_iph + sizeof(struct iphdr), 64);

	send_packet(to_send);
}

void arp_request(struct route_table_entry *route) {
	packet request;

	request.len = sizeof(struct ether_header) + sizeof(struct arp_header);
	request.interface = route->interface;

	struct ether_header* eth_header = (struct ether_header*)malloc(sizeof
		(struct ether_header));
	uint8_t *dest = (uint8_t*)malloc(6 * sizeof(uint8_t));
	for(int i = 0; i < 6; i++) {
		dest[i] = 0xFF;
	}
	memcpy(eth_header->ether_dhost, dest, 6 * sizeof(uint8_t));

	get_interface_mac(route->interface, eth_header->ether_shost);
	
	eth_header->ether_type = htons(0x0806);

	struct arp_header *arph = (struct arp_header*)malloc(sizeof
		(struct arp_header));
	arph->htype = htons(1);
	arph->ptype = htons(2048);
	arph->hlen = 6;
	arph->plen = 4;
	arph->op = htons(1);

	get_interface_mac(route->interface, arph->sha);

	struct in_addr* aux = (struct in_addr*)malloc(sizeof(struct in_addr));
	inet_aton(get_interface_ip(route->interface), aux);
	arph->spa = aux->s_addr;

	memcpy(arph->tha, dest, 6 * sizeof(uint8_t));

	arph->tpa = route->next_hop;

	memcpy(request.payload, eth_header, sizeof(struct ether_header));
	memcpy(request.payload + sizeof(struct ether_header), arph, 
		sizeof(struct arp_header));

	send_packet(&request);
}

void ippacket(packet m) {
	//Extract the payload from the packet
	struct ether_header *eth = (struct ether_header *) m.payload;

	// Start of IVP4 header
	struct iphdr *iph = ((void *) eth) + sizeof(struct ether_header);

	struct in_addr* aux = (struct in_addr*)malloc(sizeof(struct in_addr));
	inet_aton(get_interface_ip(m.interface), aux);

	//ICMP request case
	if(aux->s_addr == iph->daddr) {
		if(iph->protocol == 1) {
			struct icmphdr *icmph = (struct icmphdr*)(m.payload + 
				sizeof(struct ether_header) + sizeof(struct iphdr));
			if(icmph->type == 8) {
				icmp(&m, 0);
				return;
			}
		}
	}

	// If checksum is wrong, throw the packet
	if (ip_checksum((void *) iph, sizeof(struct iphdr)) != 0) {
		return;
	}

	// If ttl is 0 or 1, throw the packet
	if (iph->ttl == 0 || iph->ttl == 1) {
		icmp(&m, 11);
		return;
	}

	struct in_addr dest_ip;
	dest_ip.s_addr = iph->daddr;

	//Find best matching route
	struct route_table_entry *route = get_best_route(dest_ip);
	if (route == NULL) {
		icmp(&m, 3);
		return;
	}

	struct arp_entry *arp = NULL;
	for(int i = 0; i < arp_cache_size; i++) {
		if(route->next_hop == arp_cache[i].ip) {
			arp = &arp_cache[i];
			break;
		}
	}
	if (arp == NULL) {
		packet *p = (packet*)malloc(sizeof(packet));
		memcpy(p, &m, sizeof(packet));
		queue_enq(q, p);
		arp_request(route);
		return;
	}
	//Update TTL and checksum
	iph->ttl--;

	iph->check = 0;
	iph->check = ip_checksum((void *)iph, sizeof(struct iphdr));

	//Update the destination MAC address
	memcpy(eth->ether_dhost, arp->mac, 6);

	//Update the source MAC address, by getting the address of the 
	//best route interface;
	get_interface_mac(route->interface, eth->ether_shost);

	//Set packet's interface as the best route's interface
	m.interface = route->interface;

	send_packet(&m);
}

void arppacket(packet m) {
	//Extract the payload from the packet
	struct ether_header *eth = (struct ether_header *) m.payload;

	// Start of IVP4 header
	struct arp_header *arph = ((void *) eth) + sizeof(struct ether_header);

	//ARP reply
	if(ntohs(arph->op) == 2) {
		struct arp_entry* to_insert = (struct arp_entry*)malloc
			(sizeof(struct arp_entry));
		memcpy(to_insert->mac, eth->ether_shost, 6 * sizeof(uint8_t));
		to_insert->ip = arph->spa;

		memcpy(&arp_cache[arp_cache_size], to_insert, sizeof(struct arp_entry));
		arp_cache_size++;

		while(queue_empty(q) == 0) {
			packet *p = (packet*)malloc(sizeof(packet));
			p = (packet*)queue_deq(q);

			//Extract the payload from the packet
			struct ether_header *packet_eth = (struct ether_header*)p->payload;

			// Start of IVP4 header
			struct iphdr *packet_iph = ((void *) packet_eth) 
				+ sizeof(struct ether_header);

			struct in_addr dest_ip;
			dest_ip.s_addr = packet_iph->daddr;

			//Find best matching route
			struct route_table_entry *route = get_best_route(dest_ip);

			struct arp_entry *arp = NULL;
			for(int i = 0; i < arp_cache_size; i++) {
				if(route->next_hop == arp_cache[i].ip) {
					arp = &arp_cache[i];
					break;
				}
			}

			packet_iph->ttl--;
			packet_iph->check = 0;
			packet_iph->check = ip_checksum((void *) packet_iph, 
				sizeof(struct iphdr));

			memcpy(packet_eth->ether_dhost, arp->mac, 6 * sizeof(uint8_t));
			p->interface = route->interface;

			send_packet(p);
		}
	// ARP Request
	} else if(ntohs(arph->op) == 1) {;
		struct in_addr* aux = (struct in_addr*)malloc(sizeof(struct in_addr));
		inet_aton(get_interface_ip(m.interface), aux);

		if( aux->s_addr == arph->tpa ) {
			arph->op = htons(2);

			uint32_t aux;
			aux = arph->spa;
			arph->spa = arph->tpa;
			arph->tpa = aux;

			memcpy(arph->tha, arph->sha, sizeof(uint8_t)*6);

			get_interface_mac(m.interface, arph->sha);

			//Update the destination MAC address
			memcpy(eth->ether_dhost, arph->tha, 6);

			//Update the source MAC address, by getting the address of the 
			//best route interface
			get_interface_mac(m.interface, eth->ether_shost);
		}
		send_packet(&m);
	}
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");

	arp_cache = malloc(sizeof(struct arp_entry) * 100);
	DIE(arp_cache == NULL, "memory");
	arp_cache_size = 0;

	rtable_len =  read_rtable(argv[1], rtable);

	q = queue_create();

	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1) {
		//Receive a packet from an interface
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		//Extract the ethernet header from the packet
		struct ether_header *eth = (struct ether_header *) m.payload;

		if(ntohs(eth->ether_type) == 0x0800) {
			ippacket(m);
			
		} else if(ntohs(eth->ether_type) == 0x0806) {
			arppacket(m);
		}
	}
}