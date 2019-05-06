/*
 * Copyright (c) 2017 Jeremy Harris
 */
#include "tcptrace.h"

#ifdef LOAD_MODULE_STRACE

#include <sys/types.h>

extern int  strace_mod_init(int argc, char *argv[]);
extern void strace_mod_done(void);
extern void strace_mod_usage(void);

/* we'd only want tcp per-packet calls if we're going to do overlay output.  Not for now... */
#ifdef notyet
extern void strace_mod_read(struct ip *pip, tcp_pair *ptp, void *plast, void *pmodstruct);
extern void strace_mod_newfile(char * filename, u_long filesize, Bool compressed);
extern void* strace_mod_newconn(tcp_pair *ptp);
extern void strace_mode_deleteconn(tcp_pair *ptp, void *pmodstruct);
#endif

#endif	/*LOAD_MODULE_STRACE*/
