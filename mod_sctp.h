/*
 * Copyright (c) 2017 Jeremy Harris
 */
#include "tcptrace.h"

#ifdef LOAD_MODULE_SCTP

#include <sys/types.h>

extern int  sctp_mod_init(int argc, char *argv[]);
extern void sctp_mod_done(void);
extern void sctp_mod_usage(void);
extern void sctp_mod_nontcpudp_read(struct ip *pip, void *plast, u_long fpnum);

/******************************************************************************/

typedef struct sctphdr {
	uint16_t	sh_sport;
	uint16_t	sh_dport;
	uint32_t	sh_tag;
	uint32_t	sh_csum;
} sctphdr;


/* sh_type codes */
#define SC_CHUNKTYPE_DATA		0
#define SC_CHUNKTYPE_INIT		1
#define SC_CHUNKTYPE_INIT_ACK		2
#define SC_CHUNKTYPE_SACK		3
#define SC_CHUNKTYPE_HBEAT		4
#define SC_CHUNKTYPE_HBEAT_ACK		5
#define SC_CHUNKTYPE_ABORT		6
#define SC_CHUNKTYPE_SHTDN		7
#define SC_CHUNKTYPE_SHTDN_ACK		8
#define SC_CHUNKTYPE_ERROR		9
#define SC_CHUNKTYPE_COOKIE_ECHO	10
#define SC_CHUNKTYPE_COOKIE_ACK		11
#define SC_CHUNKTYPE_ECNE		12
#define SC_CHUNKTYPE_CWR		13
#define SC_CHUNKTYPE_SHTDN_COMPLETE	14


typedef struct sctp_chunk_hdr {
	uint8_t		sc_type;
	uint8_t		sc_flags;
	uint16_t	sc_len;
} sctp_chunk_hdr;

/******************/

typedef struct sctp_data {
	sctp_chunk_hdr	sd_hdr;
	uint32_t	sd_tsn;
	uint16_t	sd_stream_id;
	uint16_t	sd_stream_seq;
	uint32_t	sd_payload_id;
} sctp_data;

/******************/

typedef struct sctp_init {
	sctp_chunk_hdr	si_hdr;
	uint32_t	si_tag;
	uint32_t	si_rwnd;
	uint16_t	si_nout;
	uint16_t	si_nin;
	uint32_t	si_tsn;
} sctp_init;

/******************/

typedef struct sctp_sack {
	sctp_chunk_hdr	ss_hdr;
	uint32_t	ss_cum_tsn;
	uint32_t	ss_rwnd;
	uint16_t	ss_gapack_cnt;
	uint16_t	ss_duptsn_cnt;
} sctp_sack;

typedef struct sctp_gapack {
	uint16_t	sg_start;
	uint16_t	sg_end;
} sctp_gapack;

typedef struct sctp_duptsn {
	uint32_t	sd_tsn;
} sctp_duptsn;


/******************/

typedef struct sctp_shtdn {
	sctp_chunk_hdr	sd_hdr;
	uint32_t	sd_cum_tsn;
} sctp_shtdn;

/******************************************************************************/

typedef struct scb {
	struct sctp__pair *	sp;
	struct scb *		ptwin;

	uint32_t	tag;

	struct timeval	time;
	struct timeval	last_time;
	seqnum		min_tsn;
	seqnum		latest_tsn;

	struct timeval	hb_time;

	u_llong		packets;
	u_llong		chunks;
	u_llong		ack_chunks;

	tcp_pair_addrblock addr_pair;

	seqnum		syn, ack, fin;

	u_int		quad1, quad2, quad3, quad4;
	u_int		seq_wrap_count;

	PLOTTER		tsg_plotter;
	char *		tsg_plotfile;

	char *		host_letter;
} scb;

typedef struct sctp__pair {
	int	pair_number;

	tcp_pair_addrblock addr_pair;

	timeval	first_time, last_time;

	u_llong	packets;
	scb	a2b, b2a;

	/* connection naming information */
	char		*a_hostname;
	char		*b_hostname;
	char		*a_portname;
	char		*b_portname;
	char		*a_endpoint;
	char		*b_endpoint;
} sctp_pair;

/******************************************************************************/

extern sctp_pair * MakeSctpPair(void);
extern void FreeSctpPair(sctp_pair * ptr);

/* extern char *window_color; */
extern char *ack_color;
extern char *sack_color;
extern char *data_color;
extern char *retrans_color;
/* extern char *hw_dup_color; */
extern char *out_order_color;
extern char *text_color;
extern char *default_color;
extern char *synfin_color;
extern char *push_color;
/* extern char *ecn_color; */
/* extern char *urg_color; */
/* extern char *probe_color; */


/******************************************************************************/

#endif /* LOAD_MODULE_SCTP */
