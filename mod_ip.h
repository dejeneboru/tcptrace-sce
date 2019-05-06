/*
 * Copyright (c) 2018 Jeremy Harris
 */
#include "tcptrace.h"

#ifdef LOAD_MODULE_IP

#include <sys/types.h>

extern int  ip_mod_init(int argc, char *argv[]);
extern void ip_mod_done(void);
extern void ip_mod_usage(void);
extern void ip_mod_pkt_read(struct ip *pip, void *plast, u_long fpnum);
extern void ip_mod_tcp_read(struct ip *pip, tcp_pair *ptp, void *plast, void *pmodstruct);
extern void ip_mod_udp_read(struct ip *pip, udp_pair *ptp, void *plast, void *pmodstruct);

/******************************************************************************/

/******************************************************************************/

typedef struct icb {
	struct ip_pair *	ip;
	struct icb *		ptwin;

	struct timeval	time;
	struct timeval	last_time;
	u_llong		packets;

	tcp_pair_addrblock addr_pair;
	seqnum		ip_id;

	u_int		quad1, quad2, quad3, quad4;
	u_int		seq_wrap_count;

	PLOTTER		tsg_plotter;
	char *		tsg_plotfile;
	char *		host_letter;
} icb;

typedef struct ip_pair {
	int	pair_number;

	u_long	conn_tag;
	tcp_pair_addrblock addr_pair;

	timeval	first_time, last_time;

	u_llong	packets;
	icb	a2b, b2a;

	/* connection naming information */
	char		*a_hostname;
	char		*b_hostname;
	char		*a_portname;
	char		*b_portname;
	char		*a_endpoint;
	char		*b_endpoint;

} ip_pair;

/******************************************************************************/

extern ip_pair * MakeIpPair(void);
extern void FreeIpPair(ip_pair * ptr);

extern char *data_color;
extern char *retrans_color;
extern char *text_color;


/******************************************************************************/

#endif /* LOAD_MODULE_IP */
