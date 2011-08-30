%{
/*
  net/sched/cls_layer7.c

  Layer 7 (application layer) packet classifier.

  This program is free software.  You can redistribute and/or  modify it 
  under the terms of the GNU General Public License as published by the 
  Free Software Foundation, either version 2 of the License, or (at your 
  option) any later version.
  http://www.gnu.org/licenses/gpl.html

  Written by Matthew Strait, Ethan Sommer and Justin Levandoski, 2003.

  Modeled after:
  cls_tcindex.c:  Written 1998,1999 by Werner Almesberger, EPFL ICA

  TODO (more or less in order of priority):
  -Port to netfilter so it can be used more flexibly.
  -Allow l7-filter to change its mind as new data comes in.  Will require
  patterns to have a priority level, i.e. if "http" is priority 5 and 
  "code red" is priority 9, a packet matching both will be classified as
  "code red".
  -Better support for connections with children (FTP, etc): ability to
  classify children seperately from their parents.
  -Support IPv6 (and any other desired lower level protocols)
  -Get a better regexp implementation, one that does everything grep does.

  WISH LIST:
  -Module unloading support.  When filters are turned off, the module use
  count does not decrement.  However, this is true of other filters as well,
  such as cls_u32, so probably changes in cls_api.c is needed, which is 
  outside our realm.
  -Become more confident that our implentations of 
  layer7_(init|walk|get|dump|put|change|delete) do everything they are supposed
  to do and nothing they aren't.  Too bad there's no documentation that says
  exactly what they are supposed to do (at least none that many hours of
  searching has found).  We haven't observed any problems with our 
  implementations, but...
*/

#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/if_ether.h>
#include <net/pkt_sched.h>
#include <net/route.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/proc_fs.h>
#include <linux/ctype.h> /* Needs to be last. Else isprint() might not work (?) */
int yylex(void);
static int pattern=0;
static unsigned int window_size=8192;
static unsigned int l7_debug=0;
#define DYNWIN 1
/* don't want regexp to be a seperate module (unless someone asks for it to
be), so just inline it... */
/*
#ifdef CONFIG_NET_CLS_LAYER7_MODULE
	#include "regexp/regexp.c"
#else
	#include "regexp/regexp.h"
#endif
*/
#define LAYER7_VERSION "0.5.0"

/* See config help for info about debugging options */
#ifdef CONFIG_LAYER7_DEBUG
  #define DPRINTK(format,args...) printk(format,##args)
#else
  #define DPRINTK(format,args...)
#endif

#ifdef CONFIG_LAYER7_DEBUG_MORE
  #include <linux/time.h>
  #define DPRINTK2(format,args...) printk(format,##args)
#else
  #define DPRINTK2(format,args...)
#endif

#ifdef CONFIG_LAYER7_DEBUG_EVEN_MORE
  #define DPRINTK3(format, args...) printk(format,##args)
#else
  #define DPRINTK3(format,args...)
#endif

#define LAYER7_MAX_PATTERN_DEF_SIZE 8192
#define LAYER7_MAX_PROTOCOL_NAME_SIZE 256

/* The number of bytes to look at before giving up. */
#define LAYER7_MAX_DATA_LENGTH 1024

/* data stored from previous packets, so we can match across packets */
struct layer7_session_data {
    unsigned char data[LAYER7_MAX_DATA_LENGTH];
    int hash;
    int length;
};

/* A sliding window of sessions we are currently working on, 
 * for each new session we use the next session, until we wrap around */
/* We use static arrays rather than dynamic allocation to prevent
any possibility that a DoS attack will run us out of memory.
See the config help for more info. */
#ifdef DYNWIN
struct layer7_session_data **layer7_sessions;
#else
struct layer7_session_data layer7_sessions[CONFIG_LAYER7_SESSION_WINDOW_SIZE];
#endif
int layer7_next_session = 0;


/* Number of packets to look at before giving up.
This can get modified by writes to /proc/net/layer7_numpackets */
static int num_packets = 8;

struct layer7_filter_result {
	struct tcf_police *police;
	struct tcf_result res;
};

struct layer7_filter {
	__u16 key;
	struct layer7_filter_result result;
	struct layer7_filter *next;
};

struct layer7_data {
	struct layer7_filter_result * perfect; /* perfect hash; NULL if none */
	struct layer7_filter ** h; /* imperfect hash; only used if !perfect;
				      NULL if unused */
	__u16 mask;		/* AND key with mask */
	int shift;		/* shift ANDed key to the right */
	int hash;		/* hash table size; 0 if undefined */
	int alloc_hash;		/* allocated size */
	int fall_through;	/* 0: only classify if explicit match */
};


/* one element in the classification hash table, each connection
 * is remembered here so that it doesn't need to be reclassified 
 * for each packet once the connection has been identified */
struct ct_hashElem {
	u32 classid;
	u32 hash;
	int num_pkts_so_far;
	int classified;
	int sessionid;
	int datalen;
};

/* hash table that matches connections to the connection's state */
struct ct_hashElem currentSockets[32768];

/* a pattern defined by writing to /proc/net/layer7_protocols */
//struct layer7_pattern {
//	char * name; 
//	int patternsize;
//	unsigned char * uncomppattern; /* unsigned for consistant isprint use */
//};

/* pattern classification pair (a.k.a. filter rule) */
struct layer7_patclas_pair {
#ifdef CONFIG_LAYER7_DEBUG
	char * name;
#endif
	u32 classidtab[80];
	u32 classification;
	u32 handle;
	void * parent;
};


/* all the rules we are currently attempting to match on */
struct layer7_patclas_pair *layer7_patclas_pairs = NULL;

/* how many pairs we have so far */
int layer7_num_patclas_pairs = 0;

/* array of all the patterns which have been defined *
 * and an int to keep track of how many we have      */
struct layer7_pattern * layer7_patterns = NULL;
int layer7_num_patterns = 0;

/* the char* which holds the pattern definitions given to us 
 * through the /proc filesystem */
char * layer7_unparsed_patterns = NULL;

/* Defines a new filtering rule, for example "any packet which matches
 * the pattern called http should be classified as 0x10001".
 *
 * This is made to be memory efficent at the cost of time (it reallocates the 
 * memory each time so it only uses exactly the ammount necesary) because 
 * it will only be called one time per pattern we are matching on per boot.
 *
 * The order of the filter rules in layer7_patclas_pairs is the order they 
 * were added.
 */
static char *proto_names[100]= {"nitz",
"aim", "aimwebcontent", "applejuice", "audiogalaxy", "biff", "bittorrent", "counterstrike", 
"dhcp", "directconnect", "dns", "ftp", "gkrellm", "gnucleuslan", "gnutella", "http", "ident", 
"imap", "ipp", "irc", "jabber", "mute", "live365", "msnmessenger", "nbns", "ncp", "nntp", "pop3", 
"pressplay", "quake1", "fasttrack", "rdp", "rlogin", "rstp", "smb", "smtp", "snmp-mon", "snmp-trap", 
"snmp", "socks", "ssh", "telnet", "tftp", "validcertssl", "x11", "yahoo", "cvs", "vnc", "h323", 
"quake-halflife", "openft", "hddtemp", "mysql", "netbios", "finger", "winmx", "gopher", "edonkey", 
"bearshare", "html", "pdf", "perl", "gif", "rpm", "rtf", "ogg", "tar", "postscript", "jpeg", 
"flash", "code_red", "nimda"};
int name2id(const char *nazwa) {
	int k=0;
	int i;
for(i=0;proto_names[i];i++) 
	if (!strcmp(proto_names[i],nazwa)) { 
	k=i;break;
	};
	if (l7_debug) printk("znalazlem protokol %08x\n",k); 
	return k;
};

int strtol(char *l){
int w=0;
  for(;*l;l++){
          w*=16;
        w+=hex2dec(*l);
}
return w;
}

int hex2dec(char );
void podziel (char *s1,int *t)
{
  int l = 0,classid;
  int i, p=0, st = 0;
  char *p1;
  l = strlen (s1)+1;
  char s[2000];
  strcpy (s,s1);
 
  for (i = 0; i < l; i++)
    {
      if (st == 0)
        {
          if (s[i] == ':')
            {
              st = 1;
              s[i] = '\0';
              p1=s+p;
              p = i + 1;
            }
          continue;
        }
      if (st == 1)
        {
          if (s[i] == ':')
            {
              st = 2;
              s[i] = '\0';
              classid = strtol (s + p);
              p = i + 1;
            }
          continue;
        }
      if (st == 2)
        {
          if (s[i] == ',' || s[i] == '\0')
            {
              st = 0;
              s[i] = '\0';
              classid *= 0x10000;
              classid += strtol (s + p);
              p = i + 1;
              t[name2id(p1)]=classid;
            }
          continue;
        }
    }
}

void add_layer7_filter_rule(const char *name, const u32 classification, const u32 handle, void * parent) 
{

			/* allocate the memory for the new array */
			struct layer7_patclas_pair * newpairs = 
				kmalloc( sizeof(struct layer7_patclas_pair) * 
					 (layer7_num_patclas_pairs + 1), GFP_KERNEL);

			/* don't copy or free things if they don't exist yet*/
			if (layer7_num_patclas_pairs > 0) {
				/* copy any previously declared patterns in */
				memcpy(newpairs, layer7_patclas_pairs,
				       sizeof(struct layer7_patclas_pair) *
				       (layer7_num_patclas_pairs+1));
				
				/* free the memory the old patterns were using */
				kfree(layer7_patclas_pairs);
			}
			layer7_num_patclas_pairs++;

			/* set the newpatterns to be the authoritative patterns */
			layer7_patclas_pairs = newpairs;	
			
			/* copy in the pattern so that if it is freed we don't crash */

//			layer7_patclas_pairs[layer7_num_patclas_pairs - 1].pattern =
//				kmalloc(layer7_patterns[x].patternsize, GFP_KERNEL);
//			memcpy(layer7_patclas_pairs[layer7_num_patclas_pairs-1].pattern,
//			       layer7_patterns[x].pattern, layer7_patterns[x].patternsize);
			podziel(name,layer7_patclas_pairs[layer7_num_patclas_pairs-1].classidtab);
			#ifdef CONFIG_LAYER7_DEBUG
			layer7_patclas_pairs[layer7_num_patclas_pairs-1].name = 
				kmalloc(strlen(name)+1, GFP_KERNEL);
			strcpy(layer7_patclas_pairs[layer7_num_patclas_pairs-1].name, name); 
			#endif
			layer7_patclas_pairs[layer7_num_patclas_pairs-1].classification = 
				classification;
			layer7_patclas_pairs[layer7_num_patclas_pairs-1].handle = 
				handle;
			layer7_patclas_pairs[layer7_num_patclas_pairs-1].parent = 
				parent;
			return;
	//	}
//	}
}

/* this is a hash function which acts on the timespec to get a relatively 
 * good hash. It uses 15 bit chunks and XORs them. 
 * TODO: make the chunk size user defined so that the hash table 
 * can be bigger/smaller? */
static int layer7_hash(struct timespec ts) 
{
	int hash = (ts.tv_nsec&32767) ^ 
	  ((ts.tv_nsec>>15)&32767) ^ 
	  ((ts.tv_nsec>>30)&32767) ^ 
	  (ts.tv_sec&32767) ^ 
	  ((ts.tv_sec>>15)&32767) ^ 
	  ((ts.tv_sec>>30)&32767);
	return hash;
}

/* These functions test what kind of packet we're dealing with.
include/linux/if_ether.h suggests that all packets are treated as
Ethernet, but I'm not absolutely sure, and the presence of *raw in
skb->mac troubles me.  I depend on the IP header always starting at the
same offset, so if this is wrong, there's trouble. -MLS */

static int is_ipv4(struct sk_buff * skb)
{
	/* I'm also not convinced that this code ever gets run if
	it isn't IP, since running dhclient (which should send ARPs or 
	RARPs) doesn't cause this to return false. 
	I'm not sure what other testing I can do. */

	/* the htons is important.  It fixes the endianness */
	if(htons(skb->protocol) != ETH_P_IP)
 		return 0;

	return 1;
}

#define IP_PROTO_OFFSET 9

/* I'd rather just call this "is_tcp", except it depends on it being IPv4 and
TCP could be used on top of other protocols */
static inline int is_tcp_over_ipv4(struct sk_buff * skb)
{
	/* I don't want to depend on skb->nh.iph->protocol being set, because
	I bet it isn't when we are acting as a switch, just like skb->h.th isn't
	when acting as a router. */
	if(skb->data[ETH_HLEN + IP_PROTO_OFFSET] != IPPROTO_TCP)
		return 0;

	return 1;
}

/* Again, I'd rather just call this "is_udp"... */
static inline int is_udp_over_ipv4(struct sk_buff * skb)
{
	if(skb->data[ETH_HLEN + IP_PROTO_OFFSET] != IPPROTO_UDP)
		return 0;

	return 1;
}

static inline int is_icmp_over_ipv4(struct sk_buff * skb)
{
	if(skb->data[ETH_HLEN + IP_PROTO_OFFSET] != IPPROTO_ICMP)
		return 0;

	return 1;
}

/* Returns the number of bytes into the skb->data that the application
data starts. This is a kludge because we don't know how to do it right,
or even if there really is a right way of doing it. */
/* HLEN == hl == header length.  4 == bytes/word */
static int app_data_offset(struct sk_buff *skb)
{
	/* ip_hl = 4*skb->nh.iph->ihl would usually work, but I bet the
	iph struct isn't set when acting as a switch! */
	int ip_hl = 4*(skb->data[ETH_HLEN] & 0x0f);

	if( is_tcp_over_ipv4)
	{
		/* 12 == offset into TCP header for the header length field. We can't get this
		with skb->h.th->doff because the tcphdr struct doesn't get set when routing */
		int tcp_hl = 4*(skb->data[ETH_HLEN + ip_hl + 12] >> 4);
		return ETH_HLEN + ip_hl + tcp_hl;
	}
	else if( is_udp_over_ipv4(skb) )
		return ETH_HLEN + ip_hl + 8; /* UDP header is always 8 bytes */
	else if( is_icmp_over_ipv4(skb) )
		return ETH_HLEN + ip_hl + 8; /* ICMP header is 8 bytes */
	else
	{
		printk(KERN_ERR "layer7: tried to handle unknown protocol!\n");
		return ETH_HLEN + ip_hl + 8; /* something reasonable */
	}
}

/* This function is only called until the connection is classified or for the 
 * first few packets (whichever limit comes first.) The classification happens 
 * here. After a connection has been identified it continues to be of that 
 * type. */
static int layer7_really_classify(struct sk_buff *skb, struct tcf_result *res, int hash, void* parent)
{
 int             result;
YY_BUFFER_STATE buf_state;
        int x = 0;
        int match = 0; 
        int sid = currentSockets[hash].sessionid;

        /* the application layer data */
        unsigned char * app_data = skb->data + app_data_offset(skb);  

	int datalen = (int)skb->tail - (int)app_data ;

	/* If there's no new data, there's no way this is useful */
	if(datalen == 0) 
	{
		DPRINTK2("layer7: empty packet\n");
		goto fail;
	}
	/* If we can't fit the new data in, there's no way it's useful either */
#ifdef DYNWIN
	if(layer7_sessions[sid]->length >= LAYER7_MAX_DATA_LENGTH - 2) 
#else
	if(layer7_sessions[sid].length >= LAYER7_MAX_DATA_LENGTH - 2) 
#endif
	{
		DPRINTK2("layer7: no room left for packet\n");
		goto fail;
	}

        /* this looks slow, but changing it to a memcpy (which loses the ability to
        strip out nulls and do tolower) does not make a noticable difference in speed,
        so we suspect that this is not a bottleneck. */      
        for(x = 0; x < datalen; x++)
        {
          /* it is -2 to leave space for the null (-2, not -1?)*/
#ifdef DYNWIN
          if (layer7_sessions[sid]->length < LAYER7_MAX_DATA_LENGTH - 2) 
#else
          if (layer7_sessions[sid].length < LAYER7_MAX_DATA_LENGTH - 2) 
#endif
          { 
                if (app_data[x] != 0)
                { 
#ifdef DYNWIN
                        layer7_sessions[sid]->data[layer7_sessions[sid]->length]=tolower(app_data[x]);
                        layer7_sessions[sid]->length++;
#else
                        layer7_sessions[sid].data[layer7_sessions[sid].length]=tolower(app_data[x]);
                        layer7_sessions[sid].length++;
#endif
                }
          }     
        }       
        /* make it into a null-terminated string */
#ifdef DYNWIN
        layer7_sessions[sid]->data[layer7_sessions[sid]->length] = '\0'; 
#else
        layer7_sessions[sid].data[layer7_sessions[sid].length] = '\0'; 
#endif

#ifdef CONFIG_LAYER7_DEBUG
#ifdef DYNWIN
        if (strlen(layer7_sessions[sid]->data) != 0) {
          printk("layer7: data so far (%d packet(s), %d bytes): ('.' = non-printable)\n",
                currentSockets[hash].num_pkts_so_far, strlen(layer7_sessions[sid]->data));
          for (x = 0; x < strlen(layer7_sessions[sid]->data); x++){
            if (isprint(layer7_sessions[sid]->data[x]) && layer7_sessions[sid]->data[x] < 128) 
                printk("%c",layer7_sessions[sid]->data[x]);
#else
        if (strlen(layer7_sessions[sid].data) != 0) {
          printk("layer7: data so far (%d packet(s), %d bytes): ('.' = non-printable)\n",
                currentSockets[hash].num_pkts_so_far, strlen(layer7_sessions[sid].data));
          for (x = 0; x < strlen(layer7_sessions[sid].data); x++){
            if (isprint(layer7_sessions[sid].data[x]) && layer7_sessions[sid].data[x] < 128) 
                printk("%c",layer7_sessions[sid].data[x]);
#endif
            else                 
                printk(".");
          }
          printk("\n");
        }
        else
          printk("layer7: stream 0x%x packet %d, no data yet\n", hash, currentSockets[hash].num_pkts_so_far);
#endif

	DPRINTK2("layer7: checking for matches:\n");

        /* loop through all the patclas pairs to see if we can match it */
        for (x = 0; x < layer7_num_patclas_pairs; x++)
        {
		#ifdef CONFIG_LAYER7_DEBUG_MORE
			long int ns;
			struct timespec l7time1 /* = CURRENT_TIME */, l7time2;
			jiffies_to_timespec(jiffies,&l7time1);
		#endif
//
//                match = (layer7_patclas_pairs[x].parent == parent) && 
 //                       regexec(layer7_patclas_pairs[x].pattern, layer7_sessions[sid].data);
if (l7_debug) printk("test pakietu numcla %08x\n",layer7_num_patclas_pairs);
pattern=0;
if (layer7_patclas_pairs[x].parent == parent) {
#ifdef DYNWIN
  buf_state = yy_scan_string(layer7_sessions[sid]->data);
#else
  buf_state = yy_scan_string(layer7_sessions[sid].data);
#endif
  while ((result = yylex()) != 0);
  yy_delete_buffer(buf_state);
match=pattern;}
else
	match=0;

		#ifdef CONFIG_LAYER7_DEBUG_MORE
			jiffies_to_timespec(jiffies,&l7time2);
			/* l7time2 = CURRENT_TIME; */ /* 2.6 */
			ns = 1000000000*(int)(l7time2.tv_sec - l7time1.tv_sec) + 
			l7time2.tv_nsec - l7time1.tv_nsec;	
			if(ns != 0)
				printk("%s took %ld nanoseconds (%ld ms)\n", 
				layer7_patclas_pairs[x].name, ns, ns/1000000);
		#endif
                if (match) 
                {
                        DPRINTK("layer7: stream 0x%x: found match: %s\n", 
                                hash, layer7_patclas_pairs[x].name);
                        break;
                }
        }

	DPRINTK2("\nlayer7: done checking for matches\n");

        if(match)
        {
                /* classify it */
//                res->classid = layer7_patclas_pairs[x].classification; 
                res->classid = layer7_patclas_pairs[x].classidtab[match];
// printk( "layer7: classid %ld classid %ld\n",res->classid,layer7_patclas_pairs[x].classification);

                /* we are a "generic filter", so class is always set to 0.  
                See "Linux Network Traffic Control -- Implementation Overview",
                4 Feb 2001, section 5.3 */
                res->class = 0; 

                /* record how we classified it */
//                currentSockets[hash].classid = layer7_patclas_pairs[x].classification; 
                currentSockets[hash].classid = layer7_patclas_pairs[x].classidtab[match];
//                currentSockets[hash].classid = 0x0040000 + match;
if (l7_debug) printk("layer7: znalazl klase %d\n", match);
// printk("layer7: znalazl klase %s\n", tabela[match]);
                currentSockets[hash].hash = hash;
                currentSockets[hash].classified = 1;
                return TC_POLICE_OK;
        }

	/* Didn't try to match (no new data), or tried to match + found none */
	fail:

	DPRINTK("layer7: stream 0x%x: no match.\n", hash);

        res->class = 0;
       
        /* remember to use the default in the futrure */
        currentSockets[hash].classid=res->classid; 
        currentSockets[hash].hash = hash;

        /* this is the "unclassified" case, so leave
        currentSockets[hash].classified alone */
        return TC_POLICE_UNSPEC;
}

static int layer7_classify(struct sk_buff *skb, struct tcf_proto *tp, struct tcf_result *res)
{
	enum ip_conntrack_info ctinfo;
	struct ip_conntrack *conntrack;
	int hash;

	/* check if we can deal with the protocol */
	if( is_ipv4(skb) )
	{
		DPRINTK3("layer7: Is IPv4, going on.\n");	

		if(0); /* ugly, makes the sifting below work */
		#ifdef CONFIG_LAYER7_IPV4_UDP
		else if ( is_udp_over_ipv4(skb))
			DPRINTK3("    layer7: Is UDP/IPv4, going on.\n"); 
		#endif
		#ifdef CONFIG_LAYER7_IPV4_TCP
		else if( is_tcp_over_ipv4(skb))
			DPRINTK3("    layer7: Is TCP/IPv4, going on.\n");
		#endif
		#ifdef CONFIG_LAYER7_IPV4_ICMP
		else if( is_icmp_over_ipv4(skb))
			DPRINTK3("    layer7: Is ICMP/IPv4, going on.\n");
		#endif
		else
		{
			DPRINTK3("    layer7: Not any supported protocol, giving up.\n");
			return TC_POLICE_UNSPEC;
		}
	}
	else{
		DPRINTK2("layer7: Not IPv4, giving up.\n");
		return TC_POLICE_UNSPEC;
	}

	/* get a ip_conntrack */
	if(!(conntrack = ip_conntrack_get(skb, &ctinfo)))
	{
		printk(KERN_ERR "layer7: layer7_classify: error getting conntrack, giving up.\n");
		return TC_POLICE_UNSPEC;
	}

	/* see if we can get a master conntrack (and its master etc) 
	   (for ftp etc) */
	while (master_ct(conntrack) != NULL)  {
		conntrack = master_ct(conntrack);
	}

	/* the conntrack got bzeroed somewhere, so that should be 0
	   the first time around... */
	if (conntrack->timestamp.tv_sec == 0){
		/*conntrack->timestamp = CURRENT_TIME;*/ /* 2.4/2.6 difference */
                jiffies_to_timespec(jiffies,&conntrack->timestamp); /* 2.4/2.6 difference */

		hash = layer7_hash(conntrack->timestamp);
		memset(&currentSockets[hash], 0, sizeof(struct ct_hashElem));

                DPRINTK2("layer7: Net session 0x%x put in slot %d\n", hash, layer7_next_session);
               
                currentSockets[hash].sessionid = layer7_next_session++;
#ifdef DYNWIN
                if (layer7_next_session == window_size) 
#else
                if (layer7_next_session == CONFIG_LAYER7_SESSION_WINDOW_SIZE) 
#endif
                {
                    layer7_next_session = 0;
                    DPRINTK2("layer7: next session wrapped");
                }
#ifdef DYNWIN
                layer7_sessions[currentSockets[hash].sessionid]->length = 0;

		/* used to check for overwritten sessions being accessed */
		layer7_sessions[currentSockets[hash].sessionid]->hash = hash;
#else
                layer7_sessions[currentSockets[hash].sessionid].length = 0;

		/* used to check for overwritten sessions being accessed */
		layer7_sessions[currentSockets[hash].sessionid].hash = hash;
#endif
	}

	/* we hash on the timestamp we added to the conntrack */
	hash = layer7_hash(conntrack->timestamp);

	/* If we already know about this connection, this increments the 
	   packet count. If not, this doesn't hurt anything. */
	currentSockets[hash].num_pkts_so_far++;

        DPRINTK3("currentSockets[%x].num_pkts_so_far=%d\n",hash,currentSockets[hash].num_pkts_so_far);

        /* If we've seen this connection before and we're not trying to 
	   classify it anymore, either because we've given up or because 
	   we've found a match */
	if ( currentSockets[hash].hash == hash && 
	     (currentSockets[hash].num_pkts_so_far > num_packets ||
		currentSockets[hash].classified) )
	{
                DPRINTK3("layer7: using old classification for packet %d of stream 0x%x\n",
                        currentSockets[hash].num_pkts_so_far, hash);   

                if(currentSockets[hash].classified)
                {
                        /* classify it as what we classified it as before */
                        res->classid = currentSockets[hash].classid;
                        res->class = 0;
                        return TC_POLICE_OK;
                }
                else
                        return TC_POLICE_UNSPEC;
	}
	/* if we've seen it before, but we still need to classify it */
	else if(currentSockets[hash].hash == hash)
        {
		int retval;

		/* This happens if the following occurs: (1) a connection is opened, it is
		not classified, and has not had more than num_packets packets. (2) at least
		CONFIG_LAYER7_SESSION_WINDOW_SIZE more connections are opened, such that one 
		starts using the same slot in layer7_sessions that the first connection
		is/was using. (3) The first connection recieves another packet. 
		In this case, we simply give up on that first connection, as its old
		data has been overwritten. 
		With this system, the worst a DoS attack should be able to do is force
		all the legit connections into the default class.  */
#ifdef DYNWIN
		if(layer7_sessions[currentSockets[hash].sessionid]->hash != hash)
#else
		if(layer7_sessions[currentSockets[hash].sessionid].hash != hash)
#endif
		{
			printk(KERN_WARNING "layer7: overwritten session accessed!  If you get "
			"this message frequently, please refer to the layer 7 documentation.\n");
			retval = TC_POLICE_UNSPEC;
			
			/* never check again */
			currentSockets[hash].num_pkts_so_far = num_packets + 1; 

			return retval;
		}
		else
                	retval = layer7_really_classify(skb, res, hash,tp->root);

                if(retval == TC_POLICE_UNSPEC)
		   DPRINTK2("layer7: stream 0x%x packet #%d, still unmatched.\n", 
                       hash, currentSockets[hash].num_pkts_so_far);
		else
                    DPRINTK2("layer7: stream 0x%x packet #%d, found match. Classified as %x\n", 
                        hash, currentSockets[hash].num_pkts_so_far, currentSockets[hash].classid);

                return retval;
	}
	/* otherwise this is the first packet of a new connection */
	else{
		int retval;
	
		currentSockets[hash].num_pkts_so_far = 1;
		currentSockets[hash].classified = 0;

		retval = layer7_really_classify(skb, res, hash,tp->root);
		if(retval == TC_POLICE_UNSPEC)
                   DPRINTK2("layer7: stream 0x%x packet #1, still unmatched.\n", hash);
		else
 		   DPRINTK2("layer7: stream 0x%x packet #1. Classified as %x\n", 
                       hash, currentSockets[hash].classid);
		return retval;
	}

	return TC_POLICE_OK; /* == 0 */
}

/* Returns the "internal id" (the index into the patclas array) of the 
   rule corresponding to handle.  Untested! */
static unsigned long layer7_get(struct tcf_proto *tp, u32 handle)
{
	int x;
	/* loop through to find the corresponding rule */
	for (x = 0; x < layer7_num_patclas_pairs; x++) {
		if (layer7_patclas_pairs[x].handle == handle) 
			return x;
	}
	/* otherwise return layer7_num_patclas_pairs */
	return layer7_num_patclas_pairs;
}


/* This doesn't do anything in _any_ of the other filters either. 
(but this is one of the required functions) */
static void layer7_put(struct tcf_proto *tp, unsigned long f)
{
	DPRINTK2("layer7_put called.  Doing nothing.\n");
}

/* This actually does something, but we're not sure what.
Or rather, we know that it sets tp and that it makes tc crash if tp isn't
set, but we don't know why.  It works... (derived from tcindex.c) */
static int layer7_init(struct tcf_proto *tp)
{
	struct layer7_data *p;

	DPRINTK2("layer7_init called:  Might not be doing the right thing.\n");
	
        MOD_INC_USE_COUNT; /* not in 2.6 */
	p = kmalloc(sizeof(struct layer7_data), GFP_KERNEL);
	if (!p) {
		MOD_DEC_USE_COUNT; /* not in 2.6 */
		return -ENOMEM;
	}
	tp->root = p;
	p->perfect = NULL;
	p->h = NULL;
	p->hash = 0;
	p->mask = 0xffff;
	p->shift = 0;
	p->fall_through = 1;

	return 0;
}

/* XXX More info needed here. 
We're not sure exactly what this is supposed to do.  We're copying what 
cls_tcindex.c does and nothing appears to be broken because of this approach. */
static int layer7_delete(struct tcf_proto *tp, unsigned long arg)
{
	struct layer7_filter_result *r = (struct layer7_filter_result *) arg;
	unsigned long cl;

	DPRINTK2("layer7_delete called: might not be doing the right thing.\n");

	cl = __cls_set_class(&r->res.class,0);
	if (cl)
		tp->q->ops->cl_ops->unbind_tcf(tp->q,cl);

#ifdef NET_CLS_POLICE
	tcf_police_release(r->police);
#endif
	return 0;
}


/* There are no parameters for layer7_init, so we overload layer7_change */
static int layer7_change(struct tcf_proto * tp, unsigned long base, u32 handle,
    struct rtattr ** tca, unsigned long * arg)
{
	struct layer7_filter_result new_filter_result = {
		NULL,		/* no policing */
		{ 0,0 },	/* no classification */
	};
	struct rtattr * opt = tca[TCA_OPTIONS-1];
	struct rtattr * tb[TCA_LAYER7_MAX];
	struct layer7_filter_result * r = (struct layer7_filter_result *) * arg;
	char* protocol = NULL;
	u32 classid = 0;


	if (!opt)
		return 0;
	if(rtattr_parse(tb, TCA_LAYER7_MAX,RTA_DATA(opt), RTA_PAYLOAD(opt)) < 0)
		return -EINVAL;

	/* Get protocol here */	
	if (tb[TCA_LAYER7_PROTOCOL - 1]) {
		if (RTA_PAYLOAD(tb[TCA_LAYER7_PROTOCOL - 1]) < sizeof(int))
			return -EINVAL;
		
		protocol = (char *)RTA_DATA(tb[TCA_LAYER7_PROTOCOL - 1]);
	}
	
	r = &new_filter_result;
	
	if (tb[TCA_LAYER7_CLASSID-1]) {
		classid = *(__u32 *) RTA_DATA(tb[TCA_LAYER7_CLASSID - 1]);
        }

	DPRINTK2("add_layer7_filter_rule, protocol: %s, with classid: %x, handle %u\n", protocol, classid, handle);
	add_layer7_filter_rule(protocol, classid, handle,tp->root);

#ifdef NET_CLS_POLICE
	{
		struct tcf_police *police;

		police = tb[TCA_LAYER7_POLICE - 1] ?
		    tcf_police_locate(tb[TCA_LAYER7_POLICE - 1], NULL) : NULL;
		tcf_tree_lock(tp);
		police = xchg(&r->police, police);
		tcf_tree_unlock(tp);
		tcf_police_release(police);
	}
#endif
	return 0;
}

/* XXX More information needed here.
Can't find any documentation on what this function is supposed to do.
While the other filters do (cryptic) things here, we haven't observed
anything bad happening as a result of ours doing nothing... */
static void layer7_walk(struct tcf_proto * tp, struct tcf_walker * walker)
{
	DPRINTK2("layer7_walk called.  Not implemented.\n");
}

/* delete all the rules in the filter */
static void layer7_destroy(struct tcf_proto *tp)
{
	int x;

	/* clear the filter rules */
	if (layer7_patclas_pairs != NULL) {
		for (x=0;x<layer7_num_patclas_pairs;x++) 
		{
//			kfree(layer7_patclas_pairs[x].pattern);
		}
		kfree(layer7_patclas_pairs);
		layer7_patclas_pairs=NULL;
		layer7_num_patclas_pairs=0;
	}

	MOD_DEC_USE_COUNT;
}


/* XXX more information needed here.
This gets called each time a filter is added, but we can't find any 
documentation that defines what it is supposed to do or why it gets called
when it does.  However, nothing seems to be broken because of our current
approach. */
static int layer7_dump(struct tcf_proto *tp, unsigned long fh,
    struct sk_buff *skb, struct tcmsg *t)
{
	DPRINTK2("layer7_dump called.  Might not be doing the right thing.\n");

	return skb->len; /* cls_tcindex.c does this, don't know why... */
}

struct tcf_proto_ops cls_layer7_ops = {
	.next = NULL,
	.kind = "layer7",
	.classify = layer7_classify,
	.init = layer7_init,
	.destroy = layer7_destroy,
	.get = layer7_get,
	.put = layer7_put,
	.change = layer7_change,
	.delete = layer7_delete,
	.walk = layer7_walk,
	.dump = layer7_dump,
/*	.owner = THIS_MODULE */
};

/* converts a hex digit (ASCII) to a decimal one (int) */
int hex2dec(char c)
{
	switch (c)
	{
		case '0' ... '9':
			return c - '0';
		case 'a' ... 'f':
			return c - 'a' + 10;
		case 'A' ... 'F':
			return c - 'A' + 10;
		default:
			printk(KERN_ERR "layer7: hex2dec: bad value!\n");
			return 0;
	}
}


/* converts a "decimal" number on [0..15] to a hex digit (ASCII) */
char dec2hex(int n)
{
	switch (n)
	{
		case 0 ... 9:
			return (char)n + '0';
		case 10 ... 15:
			return (char)n - 10 + 'a';
		default:
			printk(KERN_ERR "layer7: dec2hex: bad value!\n");
			return 0;
	}
}

/* write out the patterns to userland. (yes, write reads and read writes.) */
int layer7_read_proc(char* page, char ** start, off_t off, int count, 
		     int* eof, void * data) 
{
//	if (layer7_patterns == NULL){
//		/* there are no patterns yet */
//		*eof=1;
//		page='\0';
//		return 0;
//	}
//	else{
//		int x;
//		/* there are patterns */
//		page[0]='\0';
////		for (x=0;x<layer7_num_patterns;x++){
//			int i;
//			strncat(page, layer7_patterns[x].name, strlen(layer7_patterns[x].name));
//			strncat(page, "\t", 1);
//
			/* spit it out in a friendly way.  Not necessarily exactly in the format
//			that it was inputted, but at least in all printable characters */
//			for(i = 0; i < strlen(layer7_patterns[x].uncomppattern); i++)
//			{
////				if(!isprint(layer7_patterns[x].uncomppattern[i]) || 
//				   layer7_patterns[x].uncomppattern[i] > 127)
//				{
//					char * h = "  ";
//					h[0] = dec2hex(layer7_patterns[x].uncomppattern[i]/16);
////					h[1] = dec2hex(layer7_patterns[x].uncomppattern[i]%16);
					strncat(page, "\\x", 2);
//					strncat(page, h, 2);
////				}
//				else
//				{	/* this is _really_ elegant */
//////					char * n = " ";
//					n[0] = layer7_patterns[x].uncomppattern[i];
//					strncat(page, n, 1);
//				}					
////			}
//			strncat(page,"\n", 1);
//		}
//			
//		*eof=1;
//		return strlen(page);
//	}
return 0;
}

/* Read in the protocols from userland */
int layer7_write_proc(struct file* file, const char* buffer, 
		      unsigned long count, void *data) 
{
	return 0;
}


/* taken from drivers/video/modedb.c */
int my_atoi(const char *s)
{
    int val = 0;

    for (;; s++) {
        switch (*s) {
            case '0'...'9':
                val = 10*val+(*s-'0');
                break;
            default:
                return val;
        }
    }
}

/* write out num packets to userland. */
int layer7_read_proc_np(char* page, char ** start, off_t off, int count, 
		     int* eof, void * data) 
{
	if(num_packets > 99)
		printk(KERN_ERR "layer7: NOT REACHED. num_packets too big\n");
	
	page[0] = num_packets/10 + '0';
	page[1] = num_packets%10 + '0';
	page[2] = '\n';
	page[3] = '\0';
		
	*eof=1;

	return 3;
}

/* Read in num_packets from userland */
int layer7_write_proc_np(struct file* file, const char* buffer, 
		      unsigned long count, void *data) 
{
	char * foo = (char *) kmalloc(3*sizeof(char), GFP_KERNEL);

	/* copy in the data from userland */
	copy_from_user(foo, buffer, count);

	num_packets = my_atoi(foo);

	/* This is totally arbitrary in order to make the math easier.
	   I'm lazy.  But anyway, 99 is a LOT! */
	if(num_packets > 99)
	{
		printk(KERN_WARNING "layer7: num_packets can't be > 99. Setting to 99.\n");
		num_packets = 99;
	}
	else if(num_packets < 1)
	{
		printk(KERN_WARNING "layer7: num_packets can't be < 1. Setting to 1.\n");
		num_packets = 1;
	}

	return count;
}

void layer7_cleanup_proc(void)
{
	remove_proc_entry("layer7_protocols", proc_net);
	remove_proc_entry("layer7_numpackets", proc_net);
}

/* register the proc file */
void layer7_init_proc(void)
{
	{
		struct proc_dir_entry* entry;

		/* create the file */
		entry = create_proc_entry("layer7_protocols", 0644, proc_net);

		/* set the callback functions */
		entry->read_proc = layer7_read_proc;
		entry->write_proc = layer7_write_proc;
	}

	{
		struct proc_dir_entry* entry;

		entry = create_proc_entry("layer7_numpackets", 0644, proc_net);

		entry->read_proc = layer7_read_proc_np;
		entry->write_proc = layer7_write_proc_np;
	}
}

#ifdef MODULE
int init_module(void)
{
	printk(	"layer7: layer7 module (version %s) starting. "
		"Supported protocols are:\n" 
	#ifdef CONFIG_LAYER7_IPV4_TCP
	"layer7: TCP over IPv4\n"
	#endif
	#ifdef CONFIG_LAYER7_IPV4_UDP
	"layer7: UDP over IPv4\n"
	#endif
	#ifdef CONFIG_LAYER7_IPV4_ICMP
	"layer7: ICMP over IPv4\n"
	#endif
		, LAYER7_VERSION);
	printk("Debug: %d window_size: %d num_packets %d\n",l7_debug,window_size,num_packets);
	DPRINTK ("layer7: debugging on.\n");
	DPRINTK2("layer7: more debugging on.\n");
	DPRINTK3("layer7: even more debugging on.\n");
#ifdef DYNWIN
int i;
layer7_sessions=kmalloc(sizeof(struct layer7_session_data *)*window_size, GFP_KERNEL);
for(i=0;i<window_size;i++)
layer7_sessions[i]=kmalloc(sizeof(struct layer7_session_data), GFP_KERNEL);
#endif
	layer7_init_proc();
	return register_tcf_proto_ops(&cls_layer7_ops);
}

void cleanup_module(void) 
{
	DPRINTK("layer7: cleanup_module called\n");
	layer7_cleanup_proc();
	unregister_tcf_proto_ops(&cls_layer7_ops);
#ifdef DYNWIN
int i;
for(i=0;i<window_size;i++)
kfree(layer7_sessions[i]);
kfree(layer7_sessions);

#endif

}
MODULE_LICENSE("GPL");
MODULE_PARM(l7_debug,"i");
MODULE_PARM_DESC(l7_debug,"wlacz tryb debuggera");
MODULE_PARM(window_size,"i");
MODULE_PARM_DESC(window_size,"wielkosc okna skanowania");
MODULE_PARM(num_packets,"i");
MODULE_PARM_DESC(num_packets,"ilosc skanowanych maksymalnie pakietow");
#endif
FILE *stdin=NULL;
FILE *stdout=NULL;
FILE *stderr=NULL;

#undef ECHO
#define ECHO
#define EOF -1
#define exit(k) return;
#define fprintf(a,b,m) printk( m )
#define YY_FATAL_ERROR(k)  printk(k)
#define YY_INPUT(buf,result,max_size) \
    { \
    result = YY_NULL ; \
    }
#define YY_NO_UNPUT
#define YY_MALLOC_DECL
#define malloc(k) kmalloc(k, GFP_KERNEL)
#define realloc(k,p) 0
#define free(k) kfree(k)
%}
%option noyywrap never-interactive
%%
^(\*[\x01\x02].*\x03\x0b|\*\x01.?.?.?.?\x01)|flapon|toc_signon.*0x {pattern=1;/* aim*/;yyterminate();};
user-agent:aim\/ {pattern=2;/* aimwebcontent*/;yyterminate();};
ajprot\x0d\x0a {pattern=3;/* applejuice*/;yyterminate();};
^(\x45\x5f\xd0\xd5|\x45\x5f.*0.60(6|8)W) {pattern=4;/* audiogalaxy*/;yyterminate();};
^[a-z][a-z0-9]+@[1-9][0-9]+$ {pattern=5;/* biff*/;yyterminate();};
\x13bittorrent\ protocol {pattern=6;/* bittorrent*/;yyterminate();};
cs\ .*dl.www.counter-strike.net {pattern=7;/* counterstrike*/;yyterminate();};
^(\x01|\x02)[\x01-\ ]\x06.*c\x82sc {pattern=8;/* dhcp*/;yyterminate();};
^(\$mynick\ |\$lock\ |\$key\ ) {pattern=9;/* directconnect*/;yyterminate();};
^.?.?.?.?[\x01\x02].?.?.?.?.?.?[\x01-\x3F][a-z][\x01-\x3Fa-z]*[\x02-\x06][a-z][a-z][fglmoprstuvz]?[aeop]?(um)?[\x01-\x10][\x01\x03\x04\xFF] {pattern=10;/* dns*/;yyterminate();};
^220[\x09-\x0d\ -~]*ftp {pattern=11;/* ftp*/;yyterminate();};
^\<gkrellmd_setup> {pattern=12;/* gkrellm*/;yyterminate();};
gnuclear\ connect\/[\x09-\x0d\ -~]*user-agent:\ gnucleus\ [\x09-\x0d\ -~]*lan: {pattern=13;/* gnucleuslan*/;yyterminate();};
^(gnutella\ connect\/[012]\.[0-9]\x0d\x0a[\x09-\x0d\ -~]*\x0d\x0ax-ultrapeer:|gnutella\ connect\/[012]\.[0-9]\ 200\ ok\x0d\x0a[\x09-\x0d\ -~]*\x0d\x0ax-ultrapeer:|get\ \/uri-res\/n2r\?urn:sha1:|get\ \/[\x09-\x0d\ -~]*(gwebcache|gcache|gwc)|get\ \/[\x09-\x0d\ -~]*user-agent:\ (gtk-gnutella|bearshare|mactella|gnucleus|gnotella|limewire|imesh|winmx)|get\ \/[\x09-\x0d\ -~]*content-type:\ application\/x-gnutella-packets|giv\ [0-9]*:[0-9a-f]*\/|queue\ [0-9a-f]*\ [1-9][0-9]?[0-9]?\.[1-9][0-9]?[0-9]?\.[1-9][0-9]?[0-9]?\.[1-9][0-9]?[0-9]?:[1-9][0-9]?[0-9]?[0-9]?) {pattern=14;/* gnutella*/;yyterminate();};
http\/(0\.9|1\.0|1\.1)\ [1-5][0-9][0-9]\ [\x09-\x0d\ -~]*(connection:|content-type:|content-length:)|post\ [\x09-\x0d\ -~]*\ http\/[01]\.[019] {pattern=15;/* http*/;yyterminate();};
^[1-9][0-9]?[0-9]?[0-9]?[0-9]?[\x09-\x0d]*,[\x09-\x0d]*[1-9][0-9]?[0-9]?[0-9]?[0-9]?(\x0d\x0a|[\x0d\x0a])?$ {pattern=16;/* ident*/;yyterminate();};
^(\*\ ok|a[0-9]+\ noop) {pattern=17;/* imap*/;yyterminate();};
ipp:\/\/ {pattern=18;/* ipp*/;yyterminate();};
^nick[\x09-\x0d\ -~]*user[\x09-\x0d\ -~]*: {pattern=19;/* irc*/;yyterminate();};
\<stream:stream\ [\ -~]*\ xmlns=('|\")jabber.*>\<\?xml {pattern=20;/* jabber*/;yyterminate();};
^(Public|AES)Key:\ [0-9a-f]*\x0aEnd(Public|AES)Key\x0a$ {pattern=21;/* mute*/;yyterminate();};
membername.*session.*player {pattern=22;/* live365*/;yyterminate();};
^(ver\ [0-9]+\ msnp[1-9][0-9]?\ cvr|usr\ md5\ i\ [\ -~]*) {pattern=23;/* msnmessenger*/;yyterminate();};
\x01\x10\x01|\)\x10\x01\x01|0\x10\x01 {pattern=24;/* nbns*/;yyterminate();};
^(dmdt.*\x01.*(\"\"|\x11\x11|uu)|tncp.*33) {pattern=25;/* ncp*/;yyterminate();};
^(20[01][\x09-\x0d\ -~]*AUTHINFO\ USER|20[01][\x09-\x0d\ -~]*news) {pattern=26;/* nntp*/;yyterminate();};
^(\+ok\ |-err\ ) {pattern=27;/* pop3*/;yyterminate();};
user-agent:\ nsplayer {pattern=28;/* pressplay*/;yyterminate();};
^\x80\x0c\x01quake\x03 {pattern=29;/* quake1*/;yyterminate();};
^get\ (\/.download\/[\ -~]*|\/.supernode[\ -~]|\/.status[\ -~]|\/.network[\ -~]*|\/.files|\/.hash=[0-9a-f]*\/[\ -~]*)\ http\/1.1|user-agent:\ kazaa|((kazaa|fileshare|grokster|musiccity)|(kazaa|fileshare|grokster|musiccity))|x-kazaa(-username|-network|-ip|-supernodeip|-xferid|-xferuid|tag)|^give\ [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]?[0-9]?[0-9]? {pattern=30;/* fasttrack*/;yyterminate();};
rdpdr.*cliprdp.*rdpsnd\  {pattern=31;/* rdp*/;yyterminate();};
^[a-z][a-z0-9][a-z0-9]+\/[1-9][0-9]?[0-9]?[0-9]?00 {pattern=32;/* rlogin*/;yyterminate();};
rtsp\/1.0\ 200\ ok {pattern=33;/* rstp*/;yyterminate();};
\xffsmb\x72 {pattern=34;/* smb*/;yyterminate();};
^220[\x09-\x0d\ -~]*\ (e?smtp|simple\ mail) {pattern=35;/* smtp*/;yyterminate();};
^\x02\x01\x04.+[\xa0-\xa3]\x02[\x01-\x04].?.?.?.?\x02\x01.?\x02\x01.?\x30 {pattern=36;/* snmp-mon*/;yyterminate();};
^\x02\x01\x04.+\xa4\x06.+\x40\x04.?.?.?.?\x02\x01.?\x02\x01.?\x43 {pattern=37;/* snmp-trap*/;yyterminate();};
^\x02\x01\x04.+([\xa0-\xa3]\x02[\x01-\x04].?.?.?.?\x02\x01.?\x02\x01.?\x30|\xa4\x06.+\x40\x04.?.?.?.?\x02\x01.?\x02\x01.?\x43) {pattern=38;/* snmp*/;yyterminate();};
\x05[\x01-\x08]*\x05[\x01-\x08]?.*\x05[\x01-\x03][\x01\x03].*\x05[\x01-\x08]?[\x01\x03] {pattern=39;/* socks*/;yyterminate();};
(diffie-hellman-group-exchange-sha1|diffie-hellman-group1-sha1.ssh-rsa|ssh-dssfaes128-cbc|3des-cbc|blowfish-cbc|cast128-cbc|arcfour|aes192-cbc|aes256-cbc|rijndael-cbc@lysator.liu.sefaes128-cbc|3des-cbc|blowfish-cbc|cast128-cbc|arcfour|aes192-cbc|aes256-cbc|rijndael-cbc@lysator.liu.seuhmac-md5|hmac-sha1|hmac-ripemd160)+ {pattern=40;/* ssh*/;yyterminate();};
^\xff[\xfb-\xfe].\xff[\xfb-\xfe].\xff[\xfb-\xfe] {pattern=41;/* telnet*/;yyterminate();};
^(\x01|\x02)[\ -~]*(netascii|octet|mail) {pattern=42;/* tftp*/;yyterminate();};
server-certs@thawte.com|equifax\ secure\ certificate\ authority|rsa\ data\ security,\ inc|verisign,\ inc|gte\ cybertrust\ root {pattern=43;/* validcertssl*/;yyterminate();};
^(l|B).?\x0b {pattern=44;/* x11*/;yyterminate();};
^(ymsg|ypns|yhoo).?.?.?.?.?.?.?(w|t).*\xc0\x80 {pattern=45;/* yahoo*/;yyterminate();};
^BEGIN\ (AUTH|VERIFICATION|GSSAPI)\ REQUEST\x0a {pattern=46;/* cvs*/;yyterminate();};
^rfb\ 00[1-9]\.00[0-9]\x0a$ {pattern=47;/* vnc*/;yyterminate();};
\x03..?\x08.\x18.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?\x05 {pattern=48;/* h323*/;yyterminate();};
^\xff\xff(\xff\xff)?(connect(Res)?\ \"|rcon\ )|fullserverinfo\ \"\teamplay {pattern=49;/* quake-halflife*/;yyterminate();};
x-openftalias:\ [-)(0-9a-z\ ~]|range:\ bytes= {pattern=50;/* openft*/;yyterminate();};
^\|\/dev\/[a-z][a-z][a-z]\|[0-9a-z]*\|[0-9][0-9]\|[cfk]\|$ {pattern=51;/* hddtemp*/;yyterminate();};
[\x09\x0a][0-9a-z\.\-_]+|\x01..?[a-z][a-z0-9]+ {pattern=52;/* mysql*/;yyterminate();};
\x81.?.?.[A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P][A-P] {pattern=53;/* netbios*/;yyterminate();};
$[a-z][a-z0-9\-_]+|login:\ [\x09-\x0d\ -~]*\ name:\ [\x09-\x0d\ -~]*\ Directory:\  {pattern=54;/* finger*/;yyterminate();};
\+.*p.*get {pattern=55;/* winmx*/;yyterminate();};
[1-9,\+TgI][\x09-\x0d\ -~]*\x09[\x09-\x0d\ -~]*\x09[a-z0-9\.]*\.[a-z][a-z].?.?\x09[1-9] {pattern=56;/* gopher*/;yyterminate();};
^[\xe3\xc5\xe5\xd4].?.?.?.?([\x01\x02\x05\x14\x15\x16\x18\x19\x1a\x1b\x1c\x20\x21\x32\x33\x34\x35\x46\x38\x40\x41\x42\x43\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x5b\x5c\x60\x81\x82\x90\x91\x93\x96\x97\x98\x99\x9a\x9b\x9c\x9e\xa0\xa1\xa2\xa3\xa4]|\x59................?[\ -~]|\x96....$) {pattern=57;/* edonkey*/;yyterminate();};
z9.*u>p {pattern=58;/* bearshare*/;yyterminate();};
\<html.*>\<head> {pattern=59;/* html*/;yyterminate();};
%PDF-1\.[0123456] {pattern=60;/* pdf*/;yyterminate();};
\#!\ ?\/(usr\/(local\/)?)?bin\/perl {pattern=61;/* perl*/;yyterminate();};
GIF8(7|9)a {pattern=62;/* gif*/;yyterminate();};
\xed\xab\xee\xdb.?.?.?.?[1-7] {pattern=63;/* rpm*/;yyterminate();};
\{\\rtf[12] {pattern=64;/* rtf*/;yyterminate();};
oggs.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?.?\x01vorbis {pattern=65;/* ogg*/;yyterminate();};
ustar {pattern=66;/* tar*/;yyterminate();};
%!ps {pattern=67;/* postscript*/;yyterminate();};
\xff\xd8 {pattern=68;/* jpeg*/;yyterminate();};
FWS[\x01-\x07] {pattern=69;/* flash*/;yyterminate();};
\/default\.ida\?NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u9090%u8190%u00c3%u0003%u8b00%u531b%u53ff%u0078%u0000%u00=a {pattern=70;/* code_red*/;yyterminate();};
GET\ (\/scripts\/root\.exe\?\/c\+dir|\/MSADC\/root\.exe\?\/c\+dir|\/c\/winnt\/system32\/cmd\.exe\?\/c\+dir|\/d\/winnt\/system32\/cmd\.exe\?\/c\+dir|\/scripts\/\.\.%5c\.\.\/winnt\/system32\/cmd\.exe\?\/c\+dir|\/_vti_bin\/\.\.%5c\.\.\/\.\.%5c\.\.\/\.\.%5c\.\.\/winnt\/system32\/cmd\.exe\?\/c\+dir|\/_mem_bin\/\.\.%5c\.\.\/\.\.%5c\.\.\/\.\.%5c\.\.\/winnt\/system32\/cmd\.exe\?\/c\+dir|\/msadc\/\.\.%5c\.\.\/\.\.%5c\.\.\/\.\.%5c\/\.\.\xc1\x1c\.\.\/\.\.\xc1\x1c\.\.\/\.\.\xc1\x1c\.\.\/winnt\/system32\/cmd\.exe\?\/c\+dir|\/scripts\/\.\.\xc1\x1c\.\.\/winnt\/system32\/cmd\.exe\?\/c\+dir|\/scripts\/\.\.\xc0\/\.\.\/winnt\/system32\/cmd\.exe\?\/c\+dir|\/scripts\/\.\.\xc0\xaf\.\.\/winnt\/system32\/cmd\.exe\?\/c\+dir|\/scripts\/\.\.\xc1\x9c\.\.\/winnt\/system32\/cmd\.exe\?\/c\+dir|\/scripts\/\.\.%35c\.\.\/winnt\/system32\/cmd\.exe\?\/c\+dir|\/scripts\/\.\.%35c\.\.\/winnt\/system32\/cmd\.exe\?\/c\+dir|\/scripts\/\.\.%5c\.\.\/winnt\/system32\/cmd\.exe\?\/c\+dir|\/scripts\/\.\.%2f\.\.\/winnt\/system32\/cmd\.exe\?\/c\+dir) {pattern=71;/* nimda*/;yyterminate();};
. {};
