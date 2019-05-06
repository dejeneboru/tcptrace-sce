/*
 * Copyright (c) 2017-2018 Jeremy Harris
 */
#include "tcptrace.h"

#ifdef LOAD_MODULE_SCTP

#include <sys/types.h>
#include "mod_sctp.h"

extern Bool is_icmp;

int num_sctp_pairs = -1;
sctp_pair ** spp = NULL;  /* array of pointers to allocated pairs */
int max_sctp_pairs = 64; /* initial value, automatically increases */


/* info kept for all traced packets */
struct sctp_conn_info {
  timeval	first_time;	/* time of the connection's first packet */
  timeval	last_time;	/* time of the connection's last packet */
  Bool		is_closed;	/* is the connection has been closed? */
  Bool		is_new;		/* is the connection new? */

  tcp_pair_addrblock	addr_pair;
  tcp_pair		*ptp;

  struct sctp_conn_info *prev; /* pointer to the prev connection */
  struct sctp_conn_info *next; /* pointer to the next connection */
}; 

typedef struct sctp_conn_info sctpconn;

struct sctp_info {
  timeval        last_scheduled_time;	/* time of the last network statistics  */
                                        /* as it would appear in the ideal case */
  timeval        last_actual_time;	/* time of the last network statistics  */
                                        /* when it actually happened            */
  sctpconn         *conn_head;		/* head of the list of tcp connections */
  sctpconn         *conn_tail;		/* tail of the list of tcp connections */

  u_long        open_conns;		/* number of new connections within the 
				   	   time interval */
  u_long        total_conns;		/* number of currect active connections */
};

typedef struct sctp_info sctpinfo;

struct protocol {
  u_char ip_p;
  u_llong count;
  struct protocol *next;
};

const static int sctp_update_interval = 60;

/* global variables */
static sctpinfo *mod_info;

static u_llong sctp_packets = 0;
static struct protocol *plist = NULL;

/* declarations of memory management functions for the module */
static long sctpconn_pool   = -1;

static sctpconn *
MakeRtconn(
	   void)
{
  sctpconn *ptr = NULL;

  if (sctpconn_pool < 0) sctpconn_pool = MakeMemPool(sizeof(sctpconn), 0);
  ptr = PoolMalloc(sctpconn_pool, sizeof(sctpconn));
  return ptr;
}

static void
FreeRtconn(
	   sctpconn *ptr)
{
  PoolFree(sctpconn_pool, ptr);
}


/* connection records are stored in a hash table.  Buckets are linked   */
/* lists sorted by most recent access.                                  */
#ifdef SMALL_TABLE
# define HASH_TABLE_SIZE 1021  /* oughta be prime */
#else /* SMALL_TABLE */
# define HASH_TABLE_SIZE 4099  /* oughta be prime */
#endif /* SMALL_TABLE */
static ptp_snap * ptp_hashtable[HASH_TABLE_SIZE] = {NULL};



static void
MoreSctpPairs(int num_needed)
{
    int new_max_sctp_pairs;
    int i;

    if (num_needed < max_sctp_pairs)
	return;

    new_max_sctp_pairs = max_sctp_pairs * 4;
    while (new_max_sctp_pairs < num_needed)
	new_max_sctp_pairs *= 4;
    
    if (debug)
	printf("trace: making more space for %d total SCTP pairs\n",
	       new_max_sctp_pairs);

    /* enlarge array to hold any pairs that we might create */
    spp = ReallocZ(spp,
		   max_sctp_pairs * sizeof(sctp_pair *),
		   new_max_sctp_pairs * sizeof(sctp_pair *));

    max_sctp_pairs = new_max_sctp_pairs;
}



/* Like CopyAddr() but using only the tag, in the first address
slot, and zeroes elsewhere */

static void
CopyTag(tcp_pair_addrblock *ptpa, uint32_t tag)
{
  ptpa->a_address.addr_vers = 4;
  ptpa->a_address.un.ip4.s_addr = tag;
  ptpa->b_address.addr_vers = 4;
  ptpa->b_address.un.ip4.s_addr = 0;
  ptpa->a_port = ptpa->b_port = 0;
  ptpa->hash = tag;
}



static sctp_pair *
NewSP(struct ip * pip, void * plast, struct sctphdr * sh)
{
  sctp_pair * sp = MakeSctpPair();
  sctp_chunk_hdr * sc = (void *)(sh + 1);

  sp->pair_number = ++num_sctp_pairs;

  if (num_sctp_pairs + 1 >= max_sctp_pairs) MoreSctpPairs(num_sctp_pairs+1);

  spp[num_sctp_pairs] = sp;

  CopyAddr(&sp->addr_pair, pip, ntohs(sh->sh_sport), ntohs(sh->sh_dport));

  sp->a2b.time.tv_sec = -1;
  sp->b2a.time.tv_sec = -1;

  if (filenames_shark)
    {
    sp->a2b.host_letter = "a";
    sp->b2a.host_letter = "b";
    }
  else 
    {
    sp->a2b.host_letter = strdup(NextHostLetter());
    sp->b2a.host_letter = strdup(NextHostLetter());
    }

  sp->a2b.sp = sp;
  sp->b2a.sp = sp;
  sp->a2b.ptwin = &sp->b2a;
  sp->b2a.ptwin = &sp->a2b;

  /* fill in connection name fields */
  sp->a_hostname = strdup(HostName(sp->addr_pair.a_address));
  sp->a_portname = strdup(ServiceName(sp->addr_pair.a_port));
  sp->a_endpoint = strdup(EndpointName(sp->addr_pair.a_address, sp->addr_pair.a_port));
  sp->b_hostname = strdup(HostName(sp->addr_pair.b_address));
  sp->b_portname = strdup(ServiceName(sp->addr_pair.b_port));
  sp->b_endpoint = strdup(EndpointName(sp->addr_pair.b_address, sp->addr_pair.b_port));

  /* init time sequence graphs */
  sp->a2b.tsg_plotter = sp->b2a.tsg_plotter = NO_PLOTTER;
  if (graph_tsg)
    {
    if (!ignore_non_comp
       || (  (char *)plast >= (char *)(sc + 20)		/* enough for a minimum INIT chunk */
	  && sc->sc_type == SC_CHUNKTYPE_INIT
       )  )
      {
      char title[210];

      snprintf(title, sizeof(title),"%s_==>_%s (SCTP time sequence graph)",
	      sp->a_endpoint, sp->b_endpoint);
      sp->a2b.tsg_plotter =
	  new_plotter(NULL,
	    PlotName(sp->pair_number, sp->a2b.host_letter, sp->b2a.host_letter, ""),
	    title,
	    graph_time_zero?"relative time":"time",
	    graph_seq_zero?"TSN offset":"TSN",
	    TSN_FILE_EXTENSION);
      plotter_variable(sp->a2b.tsg_plotter, "f", cur_filename);
      plotter_variable(sp->a2b.tsg_plotter, "c", "shell wireshark -g");

      snprintf(title,sizeof(title),"%s_==>_%s (SCTP time sequence graph)",
	      sp->b_endpoint, sp->a_endpoint);
      sp->b2a.tsg_plotter =
	  new_plotter(NULL,
	    PlotName(sp->pair_number, sp->b2a.host_letter, sp->a2b.host_letter, ""),
	    title,
	    graph_time_zero?"relative time":"time",
	    graph_seq_zero?"TSN offset":"TSN",
	    TSN_FILE_EXTENSION);
      plotter_variable(sp->b2a.tsg_plotter, "f", cur_filename);
      plotter_variable(sp->b2a.tsg_plotter, "c", "shell wireshark -g");

      if (graph_time_zero)
	{
	/* set graph zero points */
	plotter_nothing(sp->a2b.tsg_plotter, current_time);
	plotter_nothing(sp->b2a.tsg_plotter, current_time);
	}
      }
    }

  return sp;
}



static sctp_pair *
find_existing_SP(struct ip *pip, void * plast, struct sctphdr *sh,
    int *pdir, ptp_ptr **tcp_ptr, tcp_pair_addrblock * tpp)
{
  ptp_snap **pptph_head;
  ptp_snap *ptph;
  int dir, conn_status;
  hash hval;

  /* grab the hash value (already computed by CopyAddr) */
  hval = tpp->hash % HASH_TABLE_SIZE;
  pptph_head = &ptp_hashtable[hval];

  for (ptph = *pptph_head; ptph; )
    {
    /* See if the current node in the AVL tree hash-bucket 
     * is the exact same connection as ourselves,
     * either in A2B or B2A directions.
     */

    dir = WhichDir(tpp, &ptph->addr_pair);
    if (dir == A2B || dir == B2A)
      {
      sctp_pair *ptp = (sctp_pair *)ptph->ptp;
    
      *tcp_ptr = (ptp_ptr *)ptph->ptp;
      *pdir =
	tpp->a_address.un.ip4.s_addr == ptp->a2b.tag ? A2B :
	tpp->a_address.un.ip4.s_addr == ptp->b2a.tag ? B2A :
	dir;
      return (ptp);
      }

    /* WhichDir returned 0, meaning if it exists, it's deeper */

    conn_status = AVL_WhichDir(tpp, &ptph->addr_pair);	
    if (conn_status == LT)
	ptph = ptph->left;
    else if (conn_status == RT)
	ptph = ptph->right;
    else if (!conn_status)
      {
      fprintf(stderr, "WARNING!! AVL_WhichDir() should not return 0 if\n"
		      "\tWhichDir() didn't return A2B or B2A previously\n");
      break;
      }
    }
 
  return NULL;		/* no existing conn found */
}



static void
new_avl(tcp_pair_addrblock * tpp, sctp_pair * sp)
{
ptp_snap **pptph_head;
ptp_snap * ptph;
hash hval;

if (0)
    printf("trace.c: new_avl() calling MakePtpSnap()\n");
ptph = MakePtpSnap();

ptph->addr_pair = *tpp;
ptph->ptp = sp;

/* To insert the new connection snapshot into the AVL tree */
hval = tpp->hash % HASH_TABLE_SIZE;
pptph_head = &ptp_hashtable[hval];

if (debug > 4)
    printf("Inserting connection into hashtable:\
	 new_avl() calling SnapInsert() \n");
SnapInsert(pptph_head, ptph);
}



static sctp_pair *
FindSP(struct ip *pip, void * plast, struct sctphdr *sh,
    int *pdir, ptp_ptr **tcp_ptr, uint32_t pkt_tag, uint32_t init_tag)
{
  tcp_pair_addrblock tp_in;
  hash hval;
  sctp_pair * res;

/* printf("%s %d ptag 0x%08x itag 0x%08x\n", __FUNCTION__, __LINE__, pkt_tag, init_tag); */
  if (debug > 10)
      printf("trace.c: FindSP() called\n");

  *tcp_ptr = NULL;
  /* If it was not an INIT/ACK packet we may have an existing conn.
  Otherwise we should be creating one (using the init_tag */

  if (!init_tag)
    {
    /* Existing conn.  Check for a tag entry first.
    Fake a tpp using the packet tag */

    CopyTag(&tp_in, pkt_tag);
    if ((res = find_existing_SP(pip, plast, sh, pdir, tcp_ptr, &tp_in)))
      {
/* printf("%s %d - %p found by tag 0x%08x dir %d\n", __FUNCTION__, __LINE__, res, pkt_tag, *pdir); */
      return res;
      }

    /* No tag entry so look for an addresses entry.
    Grab the addresses from this packet */

    CopyAddr(&tp_in, pip, ntohs(sh->sh_sport), ntohs(sh->sh_dport));
    if ((res = find_existing_SP(pip, plast, sh, pdir, tcp_ptr, &tp_in)))
      {
/*printf("%s %d - %p found by addrs; b2a tag 0x%08x\n", __FUNCTION__, __LINE__, res, pkt_tag);*/
      
      res->b2a.tag = pkt_tag;

      /* Create a tag record for this direction */

      CopyTag(&tp_in, pkt_tag);
      new_avl(&tp_in, res);

      return res;
      }

/* printf("%s %d\n", __FUNCTION__, __LINE__); */
    /* No addresses entry or tag entry.  Create a new addresses entry */
    }

  /* Create a record with the addrs,ports tuple, then one with
  a tag (then all later packets for the assoc direction with that tag
  that, whatever the addrs).  Use the init tag from INIT/ACK packets
  or the verification tag otherwise. */

  res = NewSP(pip, plast, sh);
  res->a2b.tag = init_tag ? init_tag : pkt_tag;
  res->b2a.tag = 0;
/*printf("new conn; %p a2b tag 0x%08x\n", res, init_tag ? init_tag : pkt_tag);*/

  CopyAddr(&tp_in, pip, ntohs(sh->sh_sport), ntohs(sh->sh_dport));
  new_avl(&tp_in, res);

  CopyTag(&tp_in, init_tag ? init_tag : pkt_tag);
  new_avl(&tp_in, res);
 
  *pdir = A2B;
  return res;
}





void
sctp_usage(void)
{
  printf("\t-xsctp\ttrace sctp connections\n");
}

int
sctp_mod_init(int argc, char *argv[])
{
  int		i;
  Bool		enable = FALSE;

  /* look for "-xsctp" */
  for (i = 1; i < argc; ++i) {
    if (!argv[i])
      continue;  /* argument already taken by another module... */

    if (strncmp(argv[i],"-x", 2) == 0) {
      if (strncasecmp(argv[i] + 2, "sctp", 4) == 0) {
	/* I want to be called */
	enable = TRUE;
	fprintf(stderr, "mod_sctp: Capturing traffic\n");
	argv[i] = NULL;
      }
    }
  }

  if (!enable)
    return(0);	/* don't call me again */

  mod_info = (sctpinfo *)malloc(sizeof(sctpinfo));
  mod_info->last_scheduled_time = current_time;
  mod_info->last_actual_time = current_time;
  mod_info->conn_head = NULL;
  mod_info->conn_tail = NULL;
  mod_info->open_conns = 0;
  mod_info->total_conns = 0;

  /* create an array to hold any pairs that we might create */
  spp = (sctp_pair **) MallocZ(max_sctp_pairs * sizeof(sctp_pair *));

  return(1);	/* TRUE means call other sctp routines later */
}

void
sctp_mod_done(void)
{
  int ix;

  printf("\nsctp: SCTP packets - %" FS_ULL "\n", sctp_packets);

  for (ix = 0; ix <= num_sctp_pairs; ++ix) {
    sctp_pair * sp = spp[ix];

    printf("%4d: %-21s %-21s  %5ld> %5ld<\n", sp->pair_number,
      sp->a_endpoint, sp->b_endpoint,
      sp->a2b.packets, sp->b2a.packets);
  }


}



void
sctp_mod_usage(void)
{
  printf("\t-xsctp\tanalyze sctp traffic\n");
}



/* represent the sequence numbers absolute or relative to 0 */
static u_long
SeqRep(scb *pscb, u_long tsn)
{
  return graph_seq_zero ? tsn - pscb->min_tsn : tsn;
}


void
sctp_mod_nontcpudp_read(struct ip *pip, void *plast, u_long fpnum)
{
  sctphdr * sh;
  int ret;
  u_short sport, dport;
  /*uint32_t conn_tag;*/
  uint32_t init_tag = 0;
  int	dir;

  sctp_pair * sp;
  scb * thisdir, * otherdir;
  PLOTTER to_tsgpl, from_tsgpl;
  ptp_ptr * sctp_ptr = NULL;

  sctp_chunk_hdr * sc;
  ushort chunk_len;
  char        clicky_wireshark[64];

  if ((ret = getsctp(pip, &sh, &plast)) < 0) return;	/* not SCTP */

  snprintf(clicky_wireshark, sizeof(clicky_wireshark), "$c %d $f", fpnum);
  sctp_packets++;

  if ((char *)sh + sizeof(sctphdr)-1 > (char *)plast)
    {
    if (warn_printtrunc)
      fprintf(stderr, "SCTP packet %lu truncated too short to trace, ignored\n",
                    pnum);
    ++ctrunc;
    return;
    }

  /* convert fields to host byte-order */
  sport = ntohs(sh->sh_sport);
  dport = ntohs(sh->sh_dport);
  /*conn_tag = ntohl(sh->sh_tag);*/

  /* Pull the initiator-tag out of INIT or INIT_ACK chunks.  We assume
  they will be the first/only chunk in packet. */

  sc = (void *)(sh+1);
  if (!is_icmp && (char *)plast >= (char *)(sc+1))
    {
    chunk_len = ntohs(sc->sc_len);
    if (  (char *)plast >= (char *)sc + chunk_len - 1
       && (sc->sc_type == SC_CHUNKTYPE_INIT || sc->sc_type == SC_CHUNKTYPE_INIT_ACK)
       )
      {
      sctp_init * si = (void *)sc;
      init_tag = ntohl(si->si_tag);
      }
    }

  if (!(sp = FindSP(pip, plast, sh, &dir, &sctp_ptr,
		    ntohl(sh->sh_tag), init_tag)))
    return;

  if (ZERO_TIME(&sp->first_time)) sp->first_time = current_time;
  sp->last_time = current_time;

  /* figure out which direction this packet is going */
  if (dir == A2B) {
    thisdir  = &sp->a2b;
    otherdir = &sp->b2a;
  } else {
    thisdir  = &sp->b2a;
    otherdir = &sp->a2b;
  }
  to_tsgpl     = otherdir->tsg_plotter;
  from_tsgpl   = thisdir->tsg_plotter;

  if (is_icmp) {
    plotter_perm_color(from_tsgpl, out_order_color);
    plotter_uarrow(from_tsgpl, current_time, SeqRep(thisdir, thisdir->latest_tsn));
    plotter_clickarea(from_tsgpl, clicky_wireshark);
    plotter_text(from_tsgpl, current_time, SeqRep(thisdir, thisdir->latest_tsn),
                        "a", "icmp");
    plotter_info(from_tsgpl, "frame: %u", (u_int)fpnum);
    return;
  }

  thisdir->last_time = current_time;

  ++sp->packets;
  ++thisdir->packets;

if ((char *)(sh+1) != (char *)sh + 12) fprintf(stderr, "oops\n");

  for (sc = (void *)(sh+1); sc < (sctp_chunk_hdr *)plast; sc = (void *)((char *)sc + (chunk_len + 3 & ~3)))
    {
    if ((char *)plast < (char *)(sc+1))	/* cannot identify chunk type */
      {
/* fprintf(stderr, "fpnum %lu incomplete sctp_chunk_hdr\n", fpnum); */
      ++ctrunc;
      return;
      }

    chunk_len = ntohs(sc->sc_len);
/* fprintf(stderr, "fpnum %lu chunk_len %u\n", fpnum, (unsigned)chunk_len); */
    if (chunk_len == 0)
      {
      fprintf(stderr, "fpnum %lu chunk_len zero!\n", fpnum);
      return;
      }
    if ((char *)plast < (char *)sc + chunk_len - 1)
      {
/* fprintf(stderr, "fpnum %lu incomplete data (%p %p)\n", fpnum, plast, (char *)sc + chunk_len); */
      ++ctrunc;
      return;
      }

/*if (fpnum > 2441)
fprintf(stderr, "%d: %s %d\n", fpnum, __FUNCTION__, __LINE__);
*/

    ++thisdir->chunks;
    switch (sc->sc_type)
      {
      case SC_CHUNKTYPE_INIT:
	{
	sctp_init * si = (void *)sc;
	if ((char *)plast < (char *)(si+1) - 1)
	  {
	  ++ctrunc;
	  return;
	  }

	thisdir->syn = otherdir->ack = 
	thisdir->min_tsn = thisdir->latest_tsn = ntohl(si->si_tsn);

	if (from_tsgpl != NO_PLOTTER)
	  {
	  plotter_perm_color(from_tsgpl, synfin_color);
	  plotter_diamond(from_tsgpl, current_time, SeqRep(thisdir, thisdir->latest_tsn));
	  plotter_clickarea(from_tsgpl, clicky_wireshark);
	  plotter_text(from_tsgpl, current_time, SeqRep(thisdir, thisdir->latest_tsn), "a", "INI");
	  }
	break;
	}

      case SC_CHUNKTYPE_INIT_ACK:
	{
	sctp_init * si = (void *)sc;
	if ((char *)plast < (char *)(si+1) - 1)
	  {
	  ++ctrunc;
	  return;
	  }

	thisdir->syn = otherdir->ack = 
	thisdir->min_tsn = thisdir->latest_tsn = ntohl(si->si_tsn);

	if (from_tsgpl != NO_PLOTTER)
	  {
	  u_long p_tsn = SeqRep(thisdir, thisdir->latest_tsn);
	  plotter_perm_color(from_tsgpl, synfin_color);
	  plotter_diamond(from_tsgpl, current_time, p_tsn);
	  plotter_clickarea(from_tsgpl, clicky_wireshark);
	  plotter_text(from_tsgpl, current_time, p_tsn, "a", "IACK");

	  if (otherdir->syn) plotter_dot(from_tsgpl, sp->first_time, p_tsn);
	  }
	break;
	}

      case SC_CHUNKTYPE_SHTDN:
	{
	sctp_shtdn * sd = (void *)sc;
	if ((char *)plast < (char *)(sd+1) - 1)
	  {
	  ++ctrunc;
	  return;
	  }

	if (from_tsgpl != NO_PLOTTER)
	  {
	  u_long p_tsn = SeqRep(thisdir, thisdir->latest_tsn);
	  plotter_perm_color(from_tsgpl, synfin_color);
	  plotter_diamond(from_tsgpl, current_time, p_tsn);
	  plotter_text(from_tsgpl, current_time, p_tsn, "a", "SHT");
	  }

	otherdir->fin = ntohl(sd->sd_cum_tsn);
	/*XXX that was a data ack! */


	break;
	}

      case SC_CHUNKTYPE_SHTDN_ACK:
      case SC_CHUNKTYPE_SHTDN_COMPLETE:
        {
	if (from_tsgpl != NO_PLOTTER && thisdir->latest_tsn != 0)
	  {
	  plotter_perm_color(from_tsgpl, synfin_color);
	  plotter_text(from_tsgpl, current_time,
	    SeqRep(thisdir, thisdir->latest_tsn), "c",
	    sc->sc_type == SC_CHUNKTYPE_SHTDN_ACK ? "SHT_ACK" : "SHT_CMP");
	  plotter_info(to_tsgpl, "frame: %u", (u_int)fpnum);
	  }
	break;
	}

      case SC_CHUNKTYPE_DATA:
	{
	sctp_data * sd = (void *)sc;
	seqnum tsn, prev_tsn;
	Bool misorder, backorder;

	if ((char *)plast < (char *)(sd+1) - 1)
	  {
/* printf("fpnum %lu DATA trunc (%p %p)\n", fpnum, plast, sd+1); */
	  ++ctrunc;
	  return;
	  }

	tsn = ntohl(sd->sd_tsn);
	prev_tsn = thisdir->latest_tsn;
	misorder = thisdir->min_tsn != 0 && tsn - prev_tsn > 1 && tsn - prev_tsn < 1<<31;
	backorder = thisdir->min_tsn != 0 && prev_tsn - tsn < 1<<31;

	if (!backorder) thisdir->latest_tsn = tsn;
	if (thisdir->min_tsn == 0) thisdir->min_tsn = tsn;

/* printf("fpnum %lu DATA TSN %d tsgpl %p\n", fpnum, tsn, from_tsgpl); */
	if (from_tsgpl != NO_PLOTTER)
	  {
	  u_long p_tsn = SeqRep(thisdir, tsn);

	  plotter_perm_color(from_tsgpl, backorder ? retrans_color : data_color);
	  plotter_line(from_tsgpl, current_time, p_tsn - 1, current_time, p_tsn);

	  if (sd->sd_hdr.sc_flags & 1<<3)
	    plotter_htick(from_tsgpl, current_time, p_tsn);	/* delayed-ack */
	  else
	    plotter_diamond(from_tsgpl, current_time, p_tsn);	/* immediate-ack */
	  plotter_clickarea(from_tsgpl, clicky_wireshark);

	  plotter_info(from_tsgpl, "frame: %u", (u_int)fpnum);

	  if (misorder)
	    {
	    plotter_temp_color(from_tsgpl, out_order_color);
	    plotter_text(from_tsgpl, current_time, p_tsn, "a", "O");
	    }
	  /* what about the otherflags? Unordered,  frag-start, frag-end. */
	  /* sit a line above the diamond showing data size? */
	  }
	break;
	}

      case SC_CHUNKTYPE_SACK:
	{
	sctp_sack * ss = (void *)sc;
	seqnum ack;
	unsigned n_gaps, n_dups;

	if ((char *)plast < (char *)(ss+1) - 1)
	  {
/* fprintf(stderr, "fpnum %lu SACK trunc (%p %p)\n", fpnum, plast, ss+1); */
	  ++ctrunc;
	  return;
	  }
	++thisdir->ack_chunks;

	ack = ntohl(ss->ss_cum_tsn);
/* printf("fpnum %lu SACK TSN %d tsgpl %p\n", fpnum, ack, to_tsgpl); */
	n_gaps = ntohs(ss->ss_gapack_cnt);
	n_dups = ntohs(ss->ss_duptsn_cnt);

	if (to_tsgpl != NO_PLOTTER)
	  {
	  /* draw cumulative-ack line */
	  u_long p_old = SeqRep(otherdir,thisdir->ack);
	  u_long p_ack = SeqRep(otherdir,ack);

	  plotter_perm_color(to_tsgpl, ack_color);
	  if (thisdir->time.tv_sec != -1)
	    plotter_line(to_tsgpl, thisdir->time, p_old, current_time, p_old);
	  if (thisdir->time.tv_sec != -1 && thisdir->ack != ack)
	    plotter_line(to_tsgpl, current_time, p_old, current_time, p_ack);
	  else
	    plotter_dtick(to_tsgpl, current_time, p_ack);
	  plotter_clickarea(to_tsgpl, clicky_wireshark);
	  plotter_info(to_tsgpl, "frame: %u", (u_int)fpnum);

	  /* draw gap-acks */

	  if (n_gaps || n_dups) plotter_perm_color(to_tsgpl, sack_color);

	  if (n_gaps)
	    {
	    sctp_gapack * g;
	    unsigned i;

	    for (g = (void *)(ss+1), i = 1; i < n_gaps; g++, i++)
	      if ((char *)g <= (char *)ss + chunk_len)
		{
		seqnum start = ack + htons(g->sg_start);
		u_long p_start = SeqRep(otherdir, start) - 1;
		seqnum end =   ack + htons(g->sg_end);
		u_long p_end = SeqRep(otherdir, end);

		plotter_line(to_tsgpl, current_time, p_start, current_time, p_end);
		plotter_clickarea(to_tsgpl, clicky_wireshark);
		plotter_info(to_tsgpl, "frame: %u", (u_int)fpnum);
		plotter_htick(to_tsgpl, current_time, p_end);
		
		if (i == 1)
		  plotter_text(to_tsgpl, current_time, p_end, "l", "G");
		else		/* label the sequence if more than one */
		  {
		  char buf[5];
		  snprintf(buf, sizeof(buf), "%u", i);
		  plotter_text(to_tsgpl, current_time, p_end, "r", buf);
		  }
		}
	    }

	    /* draw dup-TSNs */

	    if (n_dups)
	      {
	      sctp_duptsn * d;
	      unsigned dn = 0;

	      for (d = (void *)((char *)(ss+1) + n_gaps * sizeof(sctp_gapack));
		  dn < n_dups;
		  d++, dn++)
		if ((char *)d <= (char *)ss + chunk_len)
		  {
		  seqnum dtsn = htonl(d->sd_tsn);
		  u_long p_dtsn = SeqRep(otherdir, dtsn);

		  plotter_line(to_tsgpl, current_time, p_dtsn-1, current_time, p_dtsn);
		  plotter_clickarea(to_tsgpl, clicky_wireshark);
		  plotter_info(to_tsgpl, "frame: %u", (u_int)fpnum);
		  if (dtsn > thisdir->ack)
		    plotter_ltick(to_tsgpl, current_time, p_dtsn);
		  else
		    plotter_diamond(to_tsgpl, current_time, p_dtsn);
		  if (dn == 0)
		    plotter_text(to_tsgpl, current_time, p_dtsn, "r", "D");
		  else if (dn == n_dups-1)
		    {
		    char buf[5];
		    snprintf(buf, sizeof(buf), "%u", dn);
		    plotter_text(to_tsgpl, current_time, p_dtsn, "r", buf);
		    }
		  }
	      }
	  }

	thisdir->time = current_time;
	thisdir->ack = ack;
	break;
	}

      case SC_CHUNKTYPE_HBEAT:
	{
	if (from_tsgpl != NO_PLOTTER && thisdir->latest_tsn != 0)
	  {
	  u_long p_pos = SeqRep(thisdir, thisdir->latest_tsn)-1;
	  plotter_perm_color(from_tsgpl, sack_color);
	  plotter_text(from_tsgpl, current_time, p_pos, "l", "HBT");
	  plotter_vtick(from_tsgpl, current_time, p_pos);
	  plotter_clickarea(from_tsgpl, clicky_wireshark);
	  plotter_info(from_tsgpl, "frame: %u", (u_int)fpnum);
	  }
	thisdir->hb_time = current_time;
	break;
	}

      case SC_CHUNKTYPE_HBEAT_ACK:
	{
	if (from_tsgpl != NO_PLOTTER && thisdir->latest_tsn != 0)
	  {
	  u_long p_pos = SeqRep(thisdir, thisdir->latest_tsn);
	  plotter_perm_color(from_tsgpl, sack_color);
	  plotter_text(from_tsgpl, current_time, p_pos, "a", "HBT_ACK");
	  plotter_vtick(from_tsgpl, current_time, p_pos);
	  plotter_clickarea(from_tsgpl, clicky_wireshark);
	  plotter_info(from_tsgpl, "frame: %u", (u_int)fpnum);

	  /* plot the extent of the heartbeat roundtrip under the ack line */

	  if (to_tsgpl != NO_PLOTTER)
	    {
	    plotter_perm_color(to_tsgpl, sack_color);
	    p_pos = SeqRep(otherdir, otherdir->latest_tsn)-1;
	    if (!ZERO_TIME(&otherdir->hb_time) && otherdir->latest_tsn)
	      plotter_line(to_tsgpl, otherdir->hb_time, p_pos, current_time, p_pos);
	    else
	      plotter_text(to_tsgpl, current_time, p_pos, "l", "?");
	    plotter_vtick(to_tsgpl, current_time, p_pos);
	    plotter_clickarea(to_tsgpl, clicky_wireshark);
	    plotter_info(to_tsgpl, "frame: %u", (u_int)fpnum);
	    }
	  otherdir->hb_time.tv_sec = otherdir->hb_time.tv_usec = 0;
	  }
	break;
	}

      case SC_CHUNKTYPE_ABORT:
	{
	if (from_tsgpl != NO_PLOTTER && thisdir->latest_tsn != 0)
	  {
	  plotter_perm_color(from_tsgpl, retrans_color);
	  plotter_text(from_tsgpl, current_time, SeqRep(thisdir, thisdir->latest_tsn), "c", "ABRT");
	  plotter_info(from_tsgpl, "frame: %u", (u_int)fpnum);
	  }
	break;
	}

      case SC_CHUNKTYPE_COOKIE_ECHO:
      case SC_CHUNKTYPE_COOKIE_ACK:
	{
	if (from_tsgpl != NO_PLOTTER && thisdir->latest_tsn != 0)
	  {
	  plotter_perm_color(from_tsgpl, synfin_color);
	  plotter_diamond(from_tsgpl, current_time, SeqRep(thisdir, thisdir->latest_tsn));
	  plotter_clickarea(from_tsgpl, clicky_wireshark);
	  plotter_text(from_tsgpl, current_time, SeqRep(thisdir, thisdir->latest_tsn), "a",
	    sc->sc_type == SC_CHUNKTYPE_COOKIE_ECHO ? "C_ECHO" : "C_ACK");
	  plotter_info(from_tsgpl, "frame: %u", (u_int)fpnum);
	  }
	break;
	}

      default:
	{
	if (from_tsgpl != NO_PLOTTER && thisdir->latest_tsn != 0)
	  {
	  char buf[4];
	  snprintf(buf, sizeof(buf), "?%d", sc->sc_type);
	  plotter_perm_color(from_tsgpl, retrans_color);
	  plotter_text(from_tsgpl, current_time, SeqRep(thisdir, thisdir->latest_tsn), "c", buf);
	  plotter_info(from_tsgpl, "frame: %u", (u_int)fpnum);
	  }
	break;
	}
      }
    }
}

#endif /* LOAD_MODULE_SCTP */

/* vi: ai aw sw=2
*/
