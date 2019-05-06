/*
 * Copyright (c) 2018 Jeremy Harris
 */
#include "tcptrace.h"

#ifdef LOAD_MODULE_IP

#include <sys/types.h>
#include "mod_ip.h"

int num_ip_pairs = -1;
ip_pair ** ipp = NULL;  /* array of pointers to allocated pairs */
int max_ip_pairs = 64; /* initial value, automatically increases */


/* info kept for all traced packets */
struct ip_conn_info {
  timeval	first_time;	/* time of the connection's first packet */
  timeval	last_time;	/* time of the connection's last packet */
  Bool		is_closed;	/* is the connection has been closed? */
  Bool		is_new;		/* is the connection new? */

  tcp_pair_addrblock	addr_pair;
  tcp_pair		*ptp;

  struct ip_conn_info *prev; /* pointer to the prev connection */
  struct ip_conn_info *next; /* pointer to the next connection */
}; 

typedef struct ip_conn_info ipconn;

struct ip_info {
  timeval        last_scheduled_time;	/* time of the last network statistics  */
                                        /* as it would appear in the ideal case */
  timeval        last_actual_time;	/* time of the last network statistics  */
                                        /* when it actually happened            */
  ipconn         *conn_head;		/* head of the list of tcp connections */
  ipconn         *conn_tail;		/* tail of the list of tcp connections */

  u_long        open_conns;		/* number of new connections within the 
				   	   time interval */
  u_long        total_conns;		/* number of currect active connections */
};

typedef struct ip_info ipinfo;

struct protocol {
  u_char ip_p;
  u_llong count;
  struct protocol *next;
};

const static int ip_update_interval = 60;

/* global variables */
static ipinfo *mod_info;

static u_llong ip_packets = 0;
static struct protocol *plist = NULL;

/* declarations of memory management functions for the module */
static long ipconn_pool   = -1;

static ipconn *
MakeRtconn(
	   void)
{
  ipconn *ptr = NULL;

  if (ipconn_pool < 0) ipconn_pool = MakeMemPool(sizeof(ipconn), 0);
  ptr = PoolMalloc(ipconn_pool, sizeof(ipconn));
  return ptr;
}

static void
FreeRtconn(
	   ipconn *ptr)
{
  PoolFree(ipconn_pool, ptr);
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
MoreIpPairs(int num_needed)
{
    int new_max_ip_pairs;
    int i;

    if (num_needed < max_ip_pairs)
	return;

    new_max_ip_pairs = max_ip_pairs * 4;
    while (new_max_ip_pairs < num_needed)
	new_max_ip_pairs *= 4;
    
    if (debug)
	printf("trace: making more space for %d total IP pairs\n",
	       new_max_ip_pairs);

    /* enlarge array to hold any pairs that we might create */
    ipp = ReallocZ(ipp,
		   max_ip_pairs * sizeof(ip_pair *),
		   new_max_ip_pairs * sizeof(ip_pair *));

    max_ip_pairs = new_max_ip_pairs;
}



static ip_pair *
NewIP(struct ip * pip, void * plast)
{
  ip_pair * ip = MakeIpPair();

  ip->pair_number = ++num_ip_pairs;

  if (num_ip_pairs + 1 >= max_ip_pairs) MoreIpPairs(num_ip_pairs+1);

  ipp[num_ip_pairs] = ip;

  CopyAddr(&ip->addr_pair, pip, 0, 0);

  ip->a2b.time.tv_sec = -1;
  ip->b2a.time.tv_sec = -1;

  if (filenames_shark)
    {
    ip->a2b.host_letter = "a";
    ip->b2a.host_letter = "b";
    }
  else 
    {
    ip->a2b.host_letter = strdup(NextHostLetter());
    ip->b2a.host_letter = strdup(NextHostLetter());
    }

  ip->a2b.ip = ip;
  ip->b2a.ip = ip;
  ip->a2b.ptwin = &ip->b2a;
  ip->b2a.ptwin = &ip->a2b;

  /* fill in connection name fields */
  ip->a_hostname = strdup(HostName(ip->addr_pair.a_address));
  ip->a_portname = strdup(ServiceName(0));
  ip->a_endpoint =
  strdup(EndpointName(ip->addr_pair.a_address, 0));
  ip->b_hostname = strdup(HostName(ip->addr_pair.b_address));
  ip->b_portname = strdup(ServiceName(0));
  ip->b_endpoint =
  strdup(EndpointName(ip->addr_pair.b_address, 0));

  /* init time sequence graphs */
  ip->a2b.tsg_plotter = ip->b2a.tsg_plotter = NO_PLOTTER;
  if (graph_tsg)
    {
    if (!ignore_non_comp
       || (  (char *)plast >= (char *)(pip + sizeof(struct iphdr))
       )  )
      {
      char title[210];

      snprintf(title, sizeof(title),"%s_==>_%s (IP time sequence graph)",
	      ip->a_endpoint, ip->b_endpoint);
      ip->a2b.tsg_plotter =
	  new_plotter(NULL,
	    PlotName(ip->pair_number, ip->a2b.host_letter, ip->b2a.host_letter, PLOT_FILE_EXTENSION),
	    title,
	    graph_time_zero?"relative time":"time",
	    "IP ID",
	    PLOT_FILE_EXTENSION);
      snprintf(title,sizeof(title),"%s_==>_%s (IP time sequence graph)",
	      ip->b_endpoint, ip->a_endpoint);
      ip->b2a.tsg_plotter =
	  new_plotter(NULL,
	    PlotName(ip->pair_number, ip->b2a.host_letter, ip->a2b.host_letter, PLOT_FILE_EXTENSION),
	    title,
	    graph_time_zero?"relative time":"time",
	    "IP ID",
	    PLOT_FILE_EXTENSION);

      if (graph_time_zero)
	{
	/* set graph zero points */
	plotter_nothing(ip->a2b.tsg_plotter, current_time);
	plotter_nothing(ip->b2a.tsg_plotter, current_time);
	}
      }
    }

  return ip;
}



static ip_pair *
FindIP(struct ip *pip, void * plast, int *pdir, ptp_ptr **tcp_ptr)
{
  ptp_snap **pptph_head = NULL;
  ptp_snap *ptph;
  tcp_pair_addrblock	tp_in;
  unsigned depth = 0;
  int dir, conn_status;
  hash hval;
  *tcp_ptr = NULL;

  if (debug > 10)
      printf("trace.c: FindIP() called\n");

  /* grab the address from this packet */
  CopyAddr(&tp_in, pip, 0, 0);

  /* grab the hash value (already computed by CopyAddr) */
  hval = tp_in.hash % HASH_TABLE_SIZE;

  pptph_head = &ptp_hashtable[hval];

  for (ptph = *pptph_head; ptph; )
    {
    /* See if the current node in the AVL tree hash-bucket 
     * is the exact same connection as ourselves,
     * either in A2B or B2A directions.
     */
	
    dir = WhichDir(&tp_in, &ptph->addr_pair);

    if (dir == A2B || dir == B2A)
      {
      /* OK, this looks good, suck it into memory */
    
      icb *thisdir;
      icb *otherdir;
      ip_pair *ptp;

      ptp = (ip_pair *)ptph->ptp;
    
      /* figure out which direction this packet is going */
      if (dir == A2B) {
	  thisdir  = &ptp->a2b;
	  otherdir = &ptp->b2a;
      } else {
	  thisdir  = &ptp->b2a;
	  otherdir = &ptp->a2b;
      }
    
    
      *tcp_ptr = (ptp_ptr *)ptph->ptp;
    
      *pdir = dir;
      return (ptp);
      }
    else
      {  // WhichDir returned 0, meaning if it exists, it's deeper 
      conn_status = AVL_WhichDir(&tp_in,&ptph->addr_pair);	
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
    }
 
 
  /* Didn't find it, make a new one, if possible */
  if (0)
      printf("trace.c:FindIP() calling MakePtpSnap()\n");
  ptph = MakePtpSnap();

  {
  ip_pair *tmp = NewIP(pip, plast);
  ptph->addr_pair = tmp->addr_pair;
  ptph->ptp = tmp;
  }

  /* To insert the new connection snapshot into the AVL tree */
 
  if (debug > 4)
      printf("Inserting connection into hashtable:\
	   FindIP() calling SnapInsert() \n");
  SnapInsert(pptph_head, ptph);
 
  *pdir = A2B;
  return (ip_pair *)(ptph->ptp);
}
     


void
ip_usage(void)
{
  printf("\t-xip\ttrace ip connections\n");
}

int
ip_mod_init(int argc, char *argv[])
{
  int		i;
  Bool		enable = FALSE;

  /* look for "-xip" */
  for (i = 1; i < argc; ++i) {
    if (!argv[i])
      continue;  /* argument already taken by another module... */

    if (strncmp(argv[i],"-x", 2) == 0) {
      if (strncasecmp(argv[i] + 2, "ip", 2) == 0) {
	/* I want to be called */
	enable = TRUE;
	fprintf(stderr, "mod_ip: Capturing traffic\n");
	argv[i] = NULL;
      }
    }
  }

  if (!enable)
    return(0);	/* don't call me again */

  mod_info = (ipinfo *)malloc(sizeof(ipinfo));
  mod_info->last_scheduled_time = current_time;
  mod_info->last_actual_time = current_time;
  mod_info->conn_head = NULL;
  mod_info->conn_tail = NULL;
  mod_info->open_conns = 0;
  mod_info->total_conns = 0;

  /* create an array to hold any pairs that we might create */
  ipp = (ip_pair **) MallocZ(max_ip_pairs * sizeof(ip_pair *));

  return(1);	/* TRUE means call other ip routines later */
}

void
ip_mod_done(void)
{
  fprintf(stdout, "\nip: IP packets - %" FS_ULL "\n", ip_packets);
}



void
ip_mod_usage(void)
{
  printf("\t-xip\tanalyze ip traffic\n");
}



#ifdef notdef
/* represent the sequence numbers absolute or relative to 0 */
static u_long
SeqRep(icb *pscb, u_long tsn)
{
  return graph_seq_zero ? tsn - pscb->min_tsn : tsn;
}
#endif


void
ip_mod_pkt_read(struct ip *pip, void *plast, u_long fpnum)
{
  int ret = gethdrlength(pip, &plast);
  int	dir;

  ip_pair * ip;
  icb * thisdir, * otherdir;
  PLOTTER to_tsgpl, from_tsgpl;
  ptp_ptr * ip_ptr = NULL;

  if (ret < 0) return;	/* not IP */

  ip_packets++;

  if ((char *)(pip+1) > (char *)plast)
    {
    if (warn_printtrunc)
      fprintf(stderr, "IP packet %lu truncated too short to trace, ignored\n",
                    pnum);
    ++ctrunc;
    return;
    }

  /* convert fields to host byte-order */

  if (!(ip = FindIP(pip, plast, &dir, &ip_ptr))) return;

  if (ZERO_TIME(&ip->first_time)) ip->first_time = current_time;
  ip->last_time = current_time;

  /* figure out which direction this packet is going */
  if (dir == A2B) {
    thisdir  = &ip->a2b;
    otherdir = &ip->b2a;
  } else {
    thisdir  = &ip->b2a;
    otherdir = &ip->a2b;
  }
  to_tsgpl     = otherdir->tsg_plotter;
  from_tsgpl   = thisdir->tsg_plotter;

  thisdir->last_time = current_time;

  ++ip->packets;
  ++thisdir->packets;

  if (from_tsgpl != NO_PLOTTER)
    {
    thisdir->ip_id = ntohs(pip->ip_id);

    plotter_perm_color(from_tsgpl, data_color);
    plotter_diamond(from_tsgpl, current_time, thisdir->ip_id);
    }
}

void
ip_mod_tcp_read(struct ip *pip, tcp_pair *ptp, void *plast, void *pmodstruct)
{
ip_mod_pkt_read(pip, plast, 0);
}

void
ip_mod_udp_read(struct ip *pip, udp_pair *ptp, void *plast, void *pmodstruct)
{
ip_mod_pkt_read(pip, plast, 0);
}

#endif /* LOAD_MODULE_IP */

/* vi: ai aw sw=2
*/
