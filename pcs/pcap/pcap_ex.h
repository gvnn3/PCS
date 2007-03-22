/* $Id: pcap_ex.h,v 1.6 2005/08/29 21:11:40 dugsong Exp $ */

#ifndef PCAP_EX_H
#define PCAP_EX_H

int   pcap_ex_immediate(pcap_t *pcap);
char *pcap_ex_name(char *name);
char *pcap_ex_lookupdev(char *ebuf);
int   pcap_ex_fileno(pcap_t *pcap);
void  pcap_ex_setup(pcap_t *pcap);
void  pcap_ex_setnonblock(pcap_t *pcap, int nonblock, char *ebuf);
int   pcap_ex_getnonblock(pcap_t *pcap, char *ebuf);
int   pcap_ex_next(pcap_t *pcap, struct pcap_pkthdr **hdr, u_char **pkt);
int   pcap_ex_compile_nopcap(int snaplen, int dlt, struct bpf_program *fp,
          char *str, int optimize, unsigned int netmask);

#endif /* PCAP_EX_H */
