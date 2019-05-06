/*
 * Copyright (c) 2017 Jeremy Harris
 */
#define _XOPEN_SOURCE

#include "tcptrace.h"

#ifdef LOAD_MODULE_STRACE

#include <sys/types.h>
#include <errno.h>
#include <pcre.h>
#include <time.h>
#include "mod_strace.h"

#define nelem(a) (sizeof(a) / sizeof(*a))

extern char *data_color;
extern char *ack_color;



/* Info kept for each traced connection */

typedef struct strace_conn_info {
  int		conn_number;

  timeval	first_time;
  timeval	last_time;

  int		strace_pid;
  int		strace_fd;
  seqnum	file_offset;
  char *	file_name;

  timeval	unfinished_time;
  int		call_count;

  tcp_pair_addrblock	addr_pair;
  tcp_pair		*ptp;

  /* next in hashbucket */
  struct strace_conn_info *next;

  char *	host_letter;

  PLOTTER	tsg_plotter;
  char *	tsg_plotfile;
} straceconn;


int num_strace_conns = -1;
straceconn ** stc = NULL;	/* array of pointers to conns */
int max_strace_conns = 4;	/* initial value, automatically increases */

static long straceconn_pool = -1;


/* Info for processes doing unfinished syscalls */

typedef struct strace_pid_info {
  int pid_number;
  struct strace_pid_info *next;

  int pid;
  int unfinished_fd;
} stracepid;

int num_strace_pids = -1;
stracepid ** stp = NULL;
int max_strace_pids = 2;
static long stracepid_pool = -1;




static char * stracefile = NULL;
static timeval last_actual_time;
static u_llong strace_syscall_count;


/******************************************************************************/

static straceconn *
MakeStconn(void)
{
  if (straceconn_pool < 0) straceconn_pool = MakeMemPool(sizeof(straceconn), 0);
  return PoolMalloc(straceconn_pool, sizeof(straceconn));
}

static void
FreeStconn(straceconn * ptr)
{
  PoolFree(straceconn_pool, ptr);
}

#define HASH_TABLE_SIZE 1021  /* oughta be prime */
static straceconn * conn_hashtable[HASH_TABLE_SIZE] = {NULL};

static void
MoreStraceConns(int num_needed)
{
  int new_max_strace_conns, i;

  if (num_needed < max_strace_conns)
    return;

  for (new_max_strace_conns = max_strace_conns * 4;
      new_max_strace_conns < num_needed; )
      new_max_strace_conns *= 4;

  stc = ReallocZ(stc,
		  max_strace_conns * sizeof(straceconn),
		  new_max_strace_conns * sizeof(straceconn));
  max_strace_conns = new_max_strace_conns;
}

static straceconn *
NewS(int strace_pid, int strace_fd)
{
  straceconn * conn = MakeStconn();

#ifdef debug
  printf("NewS pid %d fd %d\n", strace_pid, strace_fd);
#endif
  conn->conn_number = ++num_strace_conns;

  if (num_strace_conns + 1 >= max_strace_conns) MoreStraceConns(num_strace_conns + 1);

  stc[num_strace_conns] = conn;

  /*CopyAddr(&conn->addr_pair,  */

  if (filenames_shark)	conn->host_letter = "a";
  else			conn->host_letter = strdup(NextHostLetter());	/* hmm, only one conn, no direction info for now */

  /* conn->a_hostname = strdup(HostName(conn->addr_pair.a_address)); */
  /* conn->a_portname = strdup(ServiceName(conn->addr_pair.a_port)); */
  /* conn->a_endpoint = strdup(EndpointName(conn->addr_pair.a_address,
					    conn->addr_pair.a_port)); */

  conn->strace_pid = strace_pid;
  conn->strace_fd = strace_fd;
  conn->unfinished_time.tv_sec = -1;

  /* init time sequence graphs */
  conn->tsg_plotter =	NO_PLOTTER;
  if (graph_tsg)
    {
    char title[210];

    if (strace_pid > 0)
      snprintf(title, sizeof(title), "pid %d  fd %d", strace_pid, strace_fd);
    else
      snprintf(title, sizeof(title), "fd %d", strace_fd);
    conn->tsg_plotter = new_plotter(NULL,
			  PlotName(conn->conn_number, conn->host_letter, conn->host_letter, PLOT_FILE_EXTENSION),
			  title,
			  graph_time_zero?"relative time":"time",
			  "offset",
	      		  PLOT_FILE_EXTENSION);

    if (graph_time_zero)	/* set graph zero points */
      plotter_nothing(conn->tsg_plotter, current_time);
    }

  return conn;
}

static straceconn *
FindS(int strace_pid, int strace_fd)
{
  straceconn * conn;
  straceconn ** cp;
  hash hval;

  /* Run a linked list of conns in each hash bucket.  The TCP code
  has an avl tree off each bucket, which a) is overkill for number
  of fd's expected here, b) is odd anyway; why mix data structures? */

  hval = (strace_pid + strace_fd) % HASH_TABLE_SIZE;
  for (conn = conn_hashtable[hval]; conn; conn = conn->next)
    if (strace_fd == conn->strace_fd && strace_pid == conn->strace_pid)
      return conn;

  conn = NewS(strace_pid, strace_fd);
  cp = &conn_hashtable[hval];
  while (*cp) cp = &(*cp)->next;
  *cp = conn;
  return conn;
}

/******************************************************************************/

static stracepid *
MakeStpid(void)
{
  if (stracepid_pool < 0) stracepid_pool = MakeMemPool(sizeof(stracepid), 0);
  return PoolMalloc(stracepid_pool, sizeof(stracepid));
}

static void
FreeStpid(stracepid * ptr)
{
  PoolFree(stracepid_pool, ptr);
}

static stracepid * pid_hashtable[HASH_TABLE_SIZE] = {NULL};

static void
MoreStracePids(int num_needed)
{
  int new_max_strace_pids, i;

  if (num_needed < max_strace_pids)
    return;

  for (new_max_strace_pids = max_strace_pids * 4;
      new_max_strace_pids < num_needed; )
      new_max_strace_pids *= 4;

  stp = ReallocZ(stp,
		  max_strace_pids * sizeof(stracepid),
		  new_max_strace_pids * sizeof(stracepid));
  max_strace_pids = new_max_strace_pids;
}

static stracepid *
NewP(int strace_pid)
{
  stracepid * pid = MakeStpid();

#ifdef debug
  printf("NewP %d %p\n", strace_pid, pid);
#endif
  pid->pid_number = ++num_strace_pids;
  if (num_strace_pids + 1 >= max_strace_pids) MoreStracePids(num_strace_pids + 1);
  stp[num_strace_pids] = pid;
  return pid;
}

static stracepid *
FindP(int strace_pid)
{
  stracepid * pid;
  stracepid ** pp;
  hash hval;

  hval = strace_pid % HASH_TABLE_SIZE;
  for (pid = pid_hashtable[hval]; pid; pid = pid->next)
    if (strace_pid == pid->pid)
      return pid;

  pid = NewP(strace_pid);
  pid->pid = strace_pid;
  pid->unfinished_fd = -1;

  pp = &pid_hashtable[hval];
  while (*pp) pp = &(*pp)->next;
  *pp = pid;
  return pid;
}

/******************************************************************************/

static void
get_time(char * timestamp, int tlen, timeval * tv)
{
  char * s = index(timestamp, ':');
  if (s &&  s - timestamp < tlen)
    {		/* Colon in timestamp.  Assume hh:mm:ss.dddd  - strace -tt */
	      /*XXX could we add cmdline args for date, timezone? */
    struct tm tm;
    unsigned long decimals;
    int dend;

    memset(&tm, 0, sizeof(tm));
    s = strptime(timestamp, "%T.", &tm);
    tv->tv_sec = mktime(&tm);

    sscanf(s, "%lu%n", &decimals, &dend);

    while (dend > 6)	/* shift to get microseconds */
      {
      decimals /= 10;
      dend--;
      }
    while (dend++ < 6)
      decimals *= 10;

    tv->tv_usec = decimals;
    }
  else
    {		/* Assume ssss.dddd offset from epoch - strace -ttt */
    unsigned long sec, decimals;
    int dstart, dend;

    sscanf(timestamp, "%lu.%n%lu%n", &sec, &dstart, &decimals, &dend);

    dend -= dstart;	/* count of decimal chars */
    while (dend > 6)	/* shift to get microseconds */
      {
      decimals /= 10;
      dend--;
      }
    while (dend++ < 6)
      decimals *= 10;

    tv->tv_sec = sec;
    tv->tv_usec = decimals;
    }
  return;
}


static int
get_fd(const char * fd_string)
{
  return atoi(fd_string);
}


static void
strace_process_file(const char * filename)
{
  FILE * fp;
  char buf[8192];
  const char * patt = "^"
			"(?:(\\d+)\\s+)?"					/* 1: optional pid */
			"([0-9:.]+) "						/* 2: timestamp */
			"(?:"
    "(open|(?:read|write)v?|recv(?:from|msg)?|send(?:to|msg)?)"			/* 3: syscall name */
			  "\\("

			  "(\\d+"					/* 4: filename or fd (+maybe <filename>) */
			  "|[^\",]+"
			  "|\"[^\"]+\""
			  ")(?:<[^>]*>)?, "

			"|"
			  "<... (\\w+) resumed> "				/* 5: res call name */
			")"
			".* "
			"(?:"
			  "= (\\d+)"						/* 6: syscall result */
			  "(?: <[0-9.]+>)?"
			"|"
			  "<(unfinished) ...>"					/* 7: unfinished call */
			")"
			"$";
  pcre * re;
  int ovec[30];
  const char * errmsg;
  int erroffset;

  if (!(fp = fopen(filename, "r")))
    {
    fprintf(stderr, "failed to read '%s': %s\n", filename, strerror(errno));
    return;
    }

  /* Check the first line for a usable timestamp */
  if (fgets(buf, sizeof(buf), fp))
    if (*buf < '0' || *buf > '9')
      {
      fprintf(stderr, "timestamps needed in strace file\n");
      return;
      }

  if (!(re = pcre_compile(patt, 0, &errmsg, &erroffset, NULL)))
    {
    fprintf(stderr, "RE problem: '%s'\n"
		    "             %*s\\___ here\n"
		    "- %s\n",
      patt, erroffset, "", errmsg);
    return;
    }

  do
    {
    int n = strlen(buf);
    char * s;
    int pid;
    stracepid * p;
    straceconn * conn;
    seqnum start, end;
    Bool new = FALSE, unfinished;

#ifdef debug
    printf("%s", buf);
#endif
    if (n >= sizeof(buf)-2)
      {
      fprintf(stderr, "Input line too long\n");
      continue;
      }

    /* Check we captured at least the timestamp.  The first, pid, is
    optional */

    if (  (n = pcre_exec(re, NULL, buf, n, 0, 0, ovec, nelem(ovec))) < 5
       || ovec[4] == -1
       )
      {
#ifdef debug
      fprintf(stderr, "pcre_exec ret %d\n", n);
#endif
      exit(1);
      }
#ifdef debug
    printf("1: '%.*s'\n", ovec[3]-ovec[2], buf + ovec[2]);
    printf("2: '%.*s'\n", ovec[5]-ovec[4], buf + ovec[4]);
    printf("3: '%.*s'\n", ovec[7]-ovec[6], buf + ovec[6]);
    printf("4: '%.*s'\n", ovec[9]-ovec[8], buf + ovec[8]);
    printf("5: '%.*s'\n", ovec[11]-ovec[10], buf + ovec[10]);
    printf("6: '%.*s'\n", ovec[13]-ovec[12], buf + ovec[12]);
    printf("7: '%.*s'\n", ovec[15]-ovec[14], buf + ovec[14]);
#endif

    unfinished = ovec[14] >= 0
	      && strncmp(buf + ovec[14], "unfinished", ovec[15]-ovec[14]) == 0;
    if (!unfinished)
      strace_syscall_count++;
else

    /* pid */
    pid = ovec[2] >= 0 ? atoi(buf + ovec[2]) : 0;
    p = FindP(pid);
#ifdef debug
  printf("FindP: %p\n", p);
#endif

    /* timestamp */
    get_time(buf + ovec[4], ovec[5]-ovec[4], &current_time);

    /* fd */
    if (strncmp(buf + ovec[6], "open", 4) == 0)
      {
      new = TRUE;
      n = atoi(buf + ovec[12]);
      }
    else
      if ((n = p->unfinished_fd) == -1)
	n = atoi(buf + ovec[8]);

    conn = FindS(pid, n);
    conn->last_time = current_time;
    conn->call_count++;

    if (unfinished)
      {
      p->unfinished_fd = n;
      conn->unfinished_time = current_time;
      }
    else if (new)
      {
      conn->file_name = strndup(buf + ovec[8], ovec[9] - ovec[8]);
      conn->file_offset = 0;

      plotter_perm_color(conn->tsg_plotter, data_color);
      plotter_uarrow(conn->tsg_plotter, current_time, 0);
      plotter_darrow(conn->tsg_plotter, current_time, 0);
      plotter_text(conn->tsg_plotter, current_time, 0, "b", "open");

      plotter_perm_color(conn->tsg_plotter, ack_color);
      plotter_text(conn->tsg_plotter, current_time, 0, "a", conn->file_name);
      }
    else
      {
      Bool unf = conn->unfinished_time.tv_sec != -1;
#ifdef debug
      printf("%s\n",
	  PlotName(conn->conn_number, conn->host_letter, conn->host_letter, PLOT_FILE_EXTENSION));
#endif
      /* size (syscall result) and syscall name */
      start = conn->file_offset;
      n = atoi(buf + ovec[12]);
      end = start + n;
      plotter_perm_color(conn->tsg_plotter, data_color);
      if (unf)
	{
	plotter_line(conn->tsg_plotter, conn->unfinished_time, start, current_time, start);
	conn->unfinished_time.tv_sec = -1;
	p->unfinished_fd = -1;
	}
      plotter_darrow(conn->tsg_plotter, current_time, start);
      plotter_line(conn->tsg_plotter, current_time, start, current_time, end);
      plotter_uarrow(conn->tsg_plotter, current_time, end);
      if (unf)
	{
	buf[ovec[11]] = '\0';
	plotter_text(conn->tsg_plotter, current_time, end, "a", buf+ovec[10]);
	}
      else
	{
	buf[ovec[7]] = '\0';
	plotter_text(conn->tsg_plotter, current_time, end, "a", buf+ovec[6]);
	}

      conn->file_offset = end;
      }
#ifdef debug
    printf("\n");
#endif
    }
  while (fgets(buf, sizeof(buf), fp));

  return;
}


static void
strace_conn_stats(void)
{
  int i;
  straceconn * conn;

  for (i = 0; i <= num_strace_conns; i++)
    {
    conn = stc[i];
    printf("%5d: %4s %5d fd %5d\t%d calls\n",
      i,
      conn->strace_pid ? "pid" : "",
      conn->strace_pid,
      conn->strace_fd,
      conn->call_count);
    }
}


/******************************************************************************/

int
strace_mod_init(int argc, char *argv[])
{
  int i;

  /* look for "-xstrace <file>" */

  for (i = 1; i < argc; i++) if (argv[i])
    if (strncmp(argv[i], "-xstrace", 8) == 0)
      {
      argv[i] = NULL;
      if (++i < argc)
        {
	stracefile = argv[i];
	argv[i] = "/dev/null";
	}
      }

  if (!stracefile)
    return 0;		/* do not call me again */

  last_actual_time = current_time;

  stc = (straceconn **) MallocZ(max_strace_conns + sizeof(straceconn));
  stp = (stracepid **) MallocZ(max_strace_pids + sizeof(stracepid));

  return 1;		/* do call this module */
}

void
strace_mod_done(void)
{
  strace_process_file(stracefile);
  strace_conn_stats();
  fprintf(stderr, "\nstrace: %" FS_ULL " syscalls traced\n", strace_syscall_count);
}

void
strace_mod_usage(void)
{
  printf("\t-xstrace <file>\tanalyze file i/o in strace\n");
}

#endif	/*LOAD_MODULE_STRACE*/
/* vi: aw ai sw=2
*/
