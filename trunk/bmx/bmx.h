/*
 * Copyright (C) 2010 BMX contributors:
 * Axel Neumann
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */


#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/if.h>

#include "cyassl/sha.h"

#include "avl.h"
#include "list.h"
#include "iid.h"
#include "control.h"
#include "allocate.h"


/*
 *  from other headers:
 */

#define IDM_T int8_t // int which size does NOT matter

// dont touch this for compatibility reasons:
#define IP4_T uint32_t

#define DESCRIPTION0_ID_RANDOM_T uint64_t
#define DESCRIPTION0_ID_RANDOM_LEN sizeof( DESCRIPTION0_ID_RANDOM_T )
#define DESCRIPTION0_ID_NAME_LEN 22

#define BMX_HASH0_LEN SHA_DIGEST_SIZE  // sha.h: 20 bytes
#define BMX_PKEY0_LEN 1024

struct description_id {
	char    name[DESCRIPTION0_ID_NAME_LEN];
	union {
		uint8_t u8[DESCRIPTION0_ID_RANDOM_LEN];
		uint16_t u16[DESCRIPTION0_ID_RANDOM_LEN / sizeof(uint16_t)];
		uint32_t u32[DESCRIPTION0_ID_RANDOM_LEN / sizeof(uint32_t)];
		uint64_t u64[DESCRIPTION0_ID_RANDOM_LEN / sizeof( uint64_t)];
	} rand;
} __attribute__((packed));

struct description_hash {
	union {
		uint8_t u8[BMX_HASH0_LEN];
		uint32_t u32[BMX_HASH0_LEN/sizeof(uint32_t)];
	} h;
};

// from msg.h
#define FRAME_TYPE_ARRSZ 14


/*
 *  bmx.h:
 */


#define MIN_OGM0_SQN_RANGE 64
#define MAX_OGM0_SQN_RANGE 8192// <=> 4096 / ogm_sqn_step_size=8 * ogm_interval=1000 = ~512sec
#define DEF_OGM0_SQN_RANGE 8192// <=> 1024 / ogm_sqn_step_size=8 * ogm_interval=1000 = ~128sec

#define ARG_OGM0_SQN_RANGE "ogm0_validity_range"

#define SQN_DAD_RANGE 64 // if rcvd sqn is >= last_rcvd_sqn + SQN_TIMEOUT_RANGE then DAD
#define SQN_T uint16_t

#define MIN_SQN 0
#define MAX_SQN ((SQN_T)-1)
#define DEF_SQN 0 /* causes seqno to be randomized */


#define MIN_OGM0_PQ_BITS 0
#define MAX_OGM0_PQ_BITS 5
#define DEF_OGM0_PQ_BITS 5
#define ARG_OGM0_PQ_BITS "path_quality_bits"






#define	MIN_MASK	1
#define	MAX_MASK	32
#define ARG_MASK	"netmask"
#define ARG_NETW	"network"


#define ARG_DEBUG	"debug"
#define ARG_NO_FORK	"no_fork"
#define ARG_QUIT	"quit"

#define ARG_CONNECT "connect"
#define ARG_RUN_DIR "runtime_dir"
#define DEF_RUN_DIR "/var/run/bmx"


extern uint32_t My_pid;
#define BMX_ENV_LIB_PATH "BMX_LIB_PATH"
#define BMX_DEF_LIB_PATH "/usr/lib"
// e.g. sudo BMX_LIB_PATH="$(pwd)/lib" ./bmxd -d3 eth0:bmx
#define BMX_ENV_DEBUG "BMX_DEBUG"




#define ARG_HELP		"help"
#define ARG_VERBOSE_HELP	"verbose_help"
#define ARG_EXP			"exp_help"
#define ARG_VERBOSE_EXP		"verbose_exp_help"

#define ARG_VERSION		"version"
#define ARG_TRAILER		"trailer"

#define ARG_TEST		"test"
#define ARG_SHOW_CHANGED 	"options"


#define ARG_DEV  		"dev"
#define ARG_DEV_TTL		"ttl"
#define ARG_DEV_CLONE		"clone"
#define ARG_DEV_ANTDVSTY	"ant_diversity"
#define ARG_DEV_LL		"linklayer"
#define ARG_DEV_ANNOUNCE        "announce"
#define DEF_DEV_ANNOUNCE        YES

#define VAL_DEV_LL_LO		0
#define VAL_DEV_LL_LAN		1
#define VAL_DEV_LL_WLAN		2


#define ARG_ORIGINATORS "originators"
#define ARG_STATUS "status"
#define ARG_LINKS "links"
#define ARG_ROUTES "routes"
#define ARG_INTERFACES "interfaces"

#define ARG_THROW "throw"


#define PROBE_RANGE	1024



#define MAX_PWS 1024      /* 250 TBD: should not be larger until ogm->ws and neigh_node.packet_count (and related variables) is only 8 bit */
#define MIN_PWS 32
#define DEF_PWS 256      /* NBRF: NeighBor Ranking sequence Frame) sliding packet range of received orginator messages in squence numbers (should be a multiple of our word size) */
#define ARG_PWS "path_window_size"
extern int32_t my_pws; // my path window size used to quantify the end to end path quality between me and other nodes


#define DEF_LWS 64
#define MAX_LWS 250
#define MIN_LWS 1
#define ARG_LWS "link_window_size"
extern int32_t local_lws; // my link window size used to quantify the link qualities to direct neighbors


// the default link_lounge_size of 2 is good to compensate for ogi ~ but <= aggreg_interval
#define MIN_RTQ_LOUNGE 0
#define MAX_RTQ_LOUNGE 10
#define DEF_RTQ_LOUNGE 2
#define ARG_RTQ_LOUNGE "link_lounge_size"
extern int32_t local_rtq_lounge;

#define RQ_LINK_LOUNGE 0  /* may also be rtq_link_lounge */


#define MIN_PATH_LOUNGE 0
#define MAX_PATH_LOUNGE (0x01 << MAX_OGM0_PQ_BITS)
#define DEF_PATH_LOUNGE (0x01 << DEF_OGM0_PQ_BITS)
#define ARG_PATH_LOUNGE "path_lounge_size"
extern int32_t my_path_lounge;

#define MIN_PATH_HYST	0
#define MAX_PATH_HYST	(PROBE_RANGE)/2
#define DEF_PATH_HYST	0
#define ARG_PATH_HYST   "path_hysteresis"
extern int32_t my_path_hystere;

#define MIN_RCNT_HYST	0
#define MAX_RCNT_HYST	(PROBE_RANGE)/2
#define DEF_RCNT_HYST	10
#define ARG_RCNT_HYST   "fast_path_hysteresis"
extern int32_t my_rcnt_hystere;

#define DEF_RCNT_PWS 10
#define MIN_RCNT_PWS 2
#define MAX_RCNT_PWS 50
#define ARG_RCNT_PWS "fast_path_window_size"
extern int32_t my_rcnt_pws;


#define DEF_RCNT_FK 4
#define MIN_RCNT_FK 1
#define MAX_RCNT_FK 11
#define ARG_RCNT_FK "fast_path_faktor"
extern int32_t my_rcnt_fk;

#define MIN_LATE_PENAL 0
#define MAX_LATE_PENAL 100
#define DEF_LATE_PENAL 1
#define ARG_LATE_PENAL "lateness_penalty"
extern int32_t my_late_penalty;

#define MIN_DROP_2HLOOP NO
#define MAX_DROP_2HLOOP YES
#define DEF_DROP_2HLOOP NO
#define ARG_DROP_2HLOOP "drop_two_hop_loops"


#define DEF_DAD_TO 50000
#define MIN_DAD_TO 100
#define MAX_DAD_TO 360000000
#define ARG_DAD_TO "dad_timeout"
extern int32_t dad_to;

#define MIN_ASOCIAL NO
#define MAX_ASOCIAL YES
#define DEF_ASOCIAL NO

#define DEF_TTL 50                /* Time To Live of OGM broadcast messages */
#define MAX_TTL 63
#define MIN_TTL 1
#define ARG_TTL "ttl"
extern int32_t my_ttl;

#define DEF_WL_CLONES 200
#define MIN_WL_CLONES 0
#define MAX_WL_CLONES 400
#define ARG_WL_CLONES   "ogm_broadcasts"
extern int32_t wl_clones;

#define DEF_LAN_CLONES 100


#define DEF_ASYM_WEIGHT	100
#define MIN_ASYM_WEIGHT	0
#define MAX_ASYM_WEIGHT	100
#define ARG_ASYM_WEIGHT	"asymmetric_weight"
extern int32_t asym_weight;



#define DEF_SYM_WEIGHT	80
#define MIN_SYM_WEIGHT	0
#define MAX_SYM_WEIGHT	100
#define ARG_SYM_WEIGHT	"symmetric_weight"
extern int32_t sym_weight;

#define DEF_ASYM_EXP	1
#define MIN_ASYM_EXP	0
#define MAX_ASYM_EXP	3
#define ARG_ASYM_EXP	"asymmetric_exp"

#define DEF_HOP_PENALTY 1
#define MIN_HOP_PENALTY 0
#define MAX_HOP_PENALTY 100
#define ARG_HOP_PENALTY "hop_penalty"
extern int32_t my_hop_penalty;

#define ARG_OGI_PWRSAVE "ogi_power_save"



#define DEF_PURGE_TO  50000
#define MIN_PURGE_TO  100
#define MAX_PURGE_TO  864000000 /*10 days*/
#define ARG_PURGE_TO  "purge_timeout"
// extern int32_t purge_to;

#define MIN_DHASH_TO 300000
#define DHASH_TO_TOLERANCE_FK 10





#define OGM_AGGREG_SQN_CACHE_RANGE 64
#define OGM_AGGREG_SQN_CACHE_WARN  (OGM_AGGREG_SQN_CACHE_RANGE/2)
#define OGM_AGGREG_ARRAY_BYTE_SIZE (OGM_AGGREG_SQN_CACHE_RANGE/8)






#define SOURCE_VERSION "0.4-alpha" //put exactly one distinct word inside the string like "0.3-pre-alpha" or "0.3-rc1" or "0.3"

#define COMPAT_VERSION 11

#define IP4_STR_LEN 16

#define MAX_DBG_STR_SIZE 1500
#define OUT_SEQNO_OFFSET 1

enum NoYes {
	NO,
	YES
};

enum ADGSN {
	ADD,
	DEL,
	GET,
	SET,
	NOP
};


#define SUCCESS 0
#define FAILURE -1

extern void* FAILURE_POINTER;

#define ILLEGAL_STATE "Illegal program state. This should not happen!"

#ifndef REVISION_VERSION
#define REVISION_VERSION 0
#endif

#define MAX_SELECT_TIMEOUT_MS 400 /* MUST be smaller than (1000/2) to fit into max tv_usec */
#define CRITICAL_PURGE_TIME_DRIFT 5

#define RAND_INIT_DELAY 50
#define COMMON_OBSERVATION_WINDOW (DEF_OGM_INTERVAL*DEF_PWS)

//#define TYPE_OF_WORD unsigned long /* you should choose something big, if you don't want to waste cpu */
//#define WORD_BIT_SIZE ( sizeof(TYPE_OF_WORD) * 8 )

#define MAX( a, b ) ( (a>b) ? (a) : (b) )
#define MIN( a, b ) ( (a<b) ? (a) : (b) )

#define U32_MAX 4294967296
#define I32_MAX 2147483647
#define U16_MAX 65536
#define I16_MAX 32767
#define U8_MAX  256
#define I8_MAX  127



#define LESS_SQN( a, b )  ( ((uint16_t)( (a) - (b) ) ) >  I16_MAX )
#define LSEQ_SQN( a, b )  ( ((uint16_t)( (b) - (a) ) ) <= I16_MAX )
#define GREAT_SQN( a, b ) ( ((uint16_t)( (b) - (a) ) ) >  I16_MAX )
#define GRTEQ_SQN( a, b ) ( ((uint16_t)( (a) - (b) ) ) <= I16_MAX )

#define LESS_U32( a, b )  ( ((uint32_t)( (a) - (b) ) ) >  I32_MAX )
#define LSEQ_U32( a, b )  ( ((uint32_t)( (b) - (a) ) ) <= I32_MAX )
#define GREAT_U32( a, b ) ( ((uint32_t)( (b) - (a) ) ) >  I32_MAX )
#define GRTEQ_U32( a, b ) ( ((uint32_t)( (a) - (b) ) ) <= I32_MAX )

#define MAX_SQ( a, b ) ( (GREAT_SQN( (a), (b) )) ? (a) : (b) )




#define WARNING_PERIOD 20000

#define MAX_PATH_SIZE 300
#define MAX_ARG_SIZE 200


extern uint32_t bmx_time;
extern uint32_t bmx_time_sec;

extern uint8_t on_the_fly;


extern uint32_t s_curr_avg_cpu_load;





extern struct dev_node *primary_if;


extern struct orig_node my_orig_node;


//extern struct list_head if_list;

extern struct avl_tree dev_ip4_tree;
extern struct avl_tree dev_name_tree;

extern struct avl_tree link_tree;
extern struct avl_tree link_dev_tree;

extern struct avl_tree neigh_tree;

extern struct avl_tree dhash_tree;
extern struct avl_tree dhash_invalid_tree;

extern struct avl_tree orig_tree;
extern struct avl_tree blocked_tree;
extern struct avl_tree blacklisted_tree;





/**
 * The most important data structures
 */


struct ogm_aggreg_node {

	struct list_node list;

	struct msg_ogm_adv *ogm_advs;

	uint16_t aggregated_ogms;

	SQN_T    sqn;
	uint8_t  tx_attempts;
	uint32_t tx_timestamp;
};


struct packet_buff {

	//filled by wait4Event()
#define pkt_buff_llip4 addr.sin_addr.s_addr

	unsigned char packet_in[2001];
	struct sockaddr_in      addr;
	struct timeval		tv_stamp;
	struct dev_node	       *iif;
	int			total_length;
	uint8_t 		unicast;

	//filled in by rx_packet()
	char neigh_str[IP4_STR_LEN];
	struct dev_node        *oif;
	struct link_node       *ln;

	//filled in by rx_frm_hey0_reps() or rx_frame()
	struct link_dev_node   *lndev;

};




struct task_node
{
	struct list_node list;
	uint32_t expire;
	void (* task) (void *fpara); // pointer to the function to be executed
	void *data; //NULL or pointer to data to be given to function. Data will be freed after functio is called.
};



struct tx_task_node {
	struct list_node list;

	IP4_T    dst_ip4;
	IID_T    myIID4x;
	IID_T    neighIID4x;
	SQN_T 	 sqn;
	uint16_t frame_data_length_target; // because some variable msgs sizes may vary between scheduling and tx
	uint8_t  frame_type;
	uint8_t  tx_iterations;
	uint32_t tx_timestamp;
	struct dev_node *dev; // the outgoing interface to be used for transmitting

};

struct tx_timestamp_key {
	IP4_T myIID4x_or_dest_ip4;
	IID_T neighIID4x;
	uint16_t type;
};

struct tx_timestamp_node {
	struct tx_timestamp_key key;
	uint32_t timestamp;
};

struct dev_node
{
	struct list_node list;
	char name[IFNAMSIZ];
	char name_phy[IFNAMSIZ];

	char ip4_str[IP4_STR_LEN];

	int32_t index;

	uint8_t active;

	uint16_t  ip4_prefix_length;

	uint32_t ip4_addr;
	uint32_t ip4_tree_addr;
	uint32_t ip4_netaddr;
	uint32_t ip4_broad;
	uint32_t ip4_netmask;

	int ip4_mtu;

	int32_t rp_filter_orig;
	int32_t send_redirects_orig;


	struct sockaddr_in ip4_unicast_addr;
	struct sockaddr_in ip4_netwbrc_addr;

	int32_t unicast_sock;
	int32_t netwbrc_sock;
	int32_t fullbrc_sock;

	SQN_T packet_sqn;
	SQN_T ogm_sqn;
	uint32_t link_activity_timestamp;
	uint32_t next_powersave_hardbeat;

	uint16_t misc_flag;

	struct list_head tx_tasks_list[FRAME_TYPE_ARRSZ]; // scheduled frames and messages
	struct tx_task_node *my_tx_tasks[FRAME_TYPE_ARRSZ];
	uint16_t tx_frames_data_len_target; // target (should) length of all currently scheduled tx messages (not including packet- or frame-headers

	struct avl_tree tx_timestamp_tree; // timestamps of recently send messages, ordered by type and iid

	// having a pointer right before the following array ensures 32/64 bit alignment.
//	unsigned char *aggregation_out;
//	unsigned char aggregation_out_buff[MAX_UDPD_SIZE + 1];

//	int16_t aggregation_len;


	int8_t soft_conf_changed;
	int8_t hard_conf_changed;

	int8_t linklayer_conf;
	int8_t linklayer;

	int16_t send_clones_conf;
	int16_t send_clones;

	int16_t antenna_diversity_conf;
	int16_t antenna_diversity;

	int8_t announce_conf;
	int8_t announce;

};



struct metric_algo {
        SQN_T sqn_mask;
        SQN_T sqn_steps;                 // e.g. 2
        SQN_T sqn_window;                // MUST be given as multiple of sqn_steps
        SQN_T sqn_lounge;                // MUST be given as multiple of sqn_steps e.g. 6
        uint32_t regression; // e.g. window_size/2
        uint32_t metric_max;             // e.g. 256
};

#define SQR_RTQ 0x00
#define SQR_RQ  0x01
#define SQR_RANGE 0x02

extern struct metric_algo link_metric_algo[SQR_RANGE];

#define TQ_RATE( lndev, range) ( ((lndev)->mr[SQR_RQ].val ) ? \
(MIN( ( ((range) * ((lndev)->mr[SQR_RTQ].val) ) / ((lndev)->mr[SQR_RQ].val) ), (range) )): \
(0)  )


struct metric_record {
        SQN_T clr; // SQN upto which waightedAverageVal has been purged
	SQN_T set; 	// SQN which has been applied (if equals wa_pos) then wa_unscaled MUST NOT be set again!
	uint32_t val;
};





struct link_key {
	IP4_T llip4;
	struct dev_node *dev;
};

struct link_dev_node {
	struct list_node list;

	struct link_key key;

	uint32_t pkt_time_max;

	uint32_t rtq_time_max;

	struct link_node *link;

//	struct sq_record sqr[SQR_RANGE];

	struct metric_record mr[SQR_RANGE];

};

/* MUST be allocated and initiated all or nothing !
 * MUST be initiated with any unidirectional received OGM
 * from a direct link NB
 */
/* Only OG interfaces which are direct link neighbors have a link_node
 * Because neighboring interfaces may be seen via several of our own interfaces
 * each link_node points to one or several link_node_dev structures
 */
struct link_node
{
	uint32_t llip4;
	char llip4_str[IP4_STR_LEN];

	uint32_t pkt_time_max;
	SQN_T pkt_sqn_max;

	SQN_T rq_sqn_max;
	uint32_t rq_time_max;

	struct neigh_node *neigh;

	struct list_head lndev_list; // list with one link_node_dev element per link

};



/* Path statistics per neighbor via which OGMs of the parent orig_node have been received */
/* Every OG has one ore several neigh_nodes. */
struct router_node {

	struct link_key key;

//	SQN_T ogm_sqn_to_be_send;

	struct metric_record mr;

//	uint32_t metric;



};

struct orig_node   {

	// filled in by validate_new_link_desc0():

	struct description_id id;

	struct dhash_node *dhn;
	struct description *desc0;
//	struct orig_node *orig_key;

	uint32_t updated_timestamp; // last time this on's desc was succesfully updated
//	uint32_t referred_timestamp;// use dhn->referred_timestamp instead

	SQN_T desc0_sqn;

	SQN_T ogm_sqn_min;
	SQN_T ogm_sqn_to_be_send;
	SQN_T ogm_sqn_aggregated;

	SQN_T ogm_sqn_range;

//	SQN_T ogm_sqn_mask;
//	SQN_T ogm_sqn_steps;

	SQN_T ogm_sqn_max_rcvd;

	uint8_t ogm_sqn_pq_bits;

	struct metric_algo path_metric_algo;

	uint8_t blocked;

	// not yet filled in:

	// filled in by process_desc0_tlvs()->

	uint32_t primary_ip4;
	char primary_ip4_str[IP4_STR_LEN];


	// filled in by ???


	struct link_key router_key;   // the neighbor which is the currently best_next_hop
	struct avl_tree router_tree;
	uint32_t router_path_metric;


/*
	// old unused:




	uint32_t last_aware;              // when last valid ogm via  this node was received
	uint32_t last_valid_time;         // when last valid ogm from this node was received

	uint32_t first_valid_sec;         // only used for debugging purposes

	SQN_T last_decided_sqn;
	SQN_T last_accepted_sqn;          // last squence number acceppted for metric
	SQN_T last_valid_sqn;             // last and best known squence number
	SQN_T last_wavg_sqn;              // last sequence number used for estimating ogi

	uint8_t last_path_ttl;
	int8_t last_path_change_scenario;

	uint8_t  pws;
	uint8_t  path_lounge;
	uint8_t path_hystere;
	uint8_t late_penalty;

	uint8_t rcnt_pws;
	uint8_t rcnt_hystere;
	uint8_t rcnt_fk;

	uint32_t ogi_wavg;
	uint32_t rt_changes;
*/
	/*size of plugin data is defined during intialization and depends on registered plugin-data hooks */
	void *plugin_data[];

};


struct neigh_node {

	struct neigh_node *nnkey;

	struct avl_tree link_tree;

	struct dhash_node *dhn;


	// filled in by ???:

	IID_T neighIID4me;
	IID_T neighIID4neigh;

	struct iid_repos neighIID4x_repos;

	// filled in by ???:
	struct link_dev_node *best_rtq;

	// filled in by ???:
	SQN_T ogm_aggregation_rcvd_max;
	uint8_t ogm_aggregations_acked[OGM_AGGREG_ARRAY_BYTE_SIZE];
	uint8_t ogm_aggregations_rcvd[OGM_AGGREG_ARRAY_BYTE_SIZE];

};


struct dhash_node {

	struct description_hash dhash;

	// filled in by rx_frm_hiX0_advs() -> get_orig_node():

	uint32_t referred_timestamp; // last time this dhn was referred

	struct neigh_node *neigh;

	IID_T myIID4orig;


	// filled in by rx_frm_hi40_reps():

	struct orig_node *on;

	// filled in by expire_dhash_node()
	// uint8_t invalid; equal to on == NULL
};


struct black_node {

	struct description_hash dhash;
};




/* list element to store all the disabled tunnel rule netmasks */
struct throw_node
{
	struct list_node list;
	uint32_t addr;
	uint8_t  netmask;
};




# define timercpy(d, a) (d)->tv_sec = (a)->tv_sec; (d)->tv_usec = (a)->tv_usec;



enum {
	CLEANUP_SUCCESS,
	CLEANUP_FAILURE,
	CLEANUP_MY_SIGSEV,
	CLEANUP_RETURN
};

/*
 * PARANOIA ERROR CODES:
 * Negative numbers are used as SIGSEV error codes !
 * Currently used numbers are: -500000 ... -500501
 */

#ifdef NO_PARANOIA
#define paranoia( ... )
#define assertion( ... )
#define ASSERTION( ... )
#else
#define paranoia( code , problem ); do { if ( (problem) ) { cleanup_all( code ); } }while(0)
#define assertion( code , condition ); do { if ( !(condition) ) { cleanup_all( code ); } }while(0)
#ifdef EXTREME_PARANOIA
#define ASSERTION( code , condition ); do { if ( !(condition) ) { cleanup_all( code ); } }while(0)
#define CHECK_INTEGRITY( ... ) checkIntegrity()
#else
#define CHECK_INTEGRITY( ... )
#define ASSERTION( ... )
#endif
#endif


#ifndef PROFILING
#define STATIC_FUNC static
#else
#define STATIC_FUNC
#endif

#ifdef STATIC_VARIABLES
#define STATIC_VAR static
#else
#define STATIC_VAR
#endif

/***********************************************************
 Data Infrastructure
 ************************************************************/

void blacklist_neighbor(struct packet_buff *pb);

IDM_T blacklisted_neighbor(struct packet_buff *pb, struct description_hash *dhash);

IDM_T validate_metric_algo(struct metric_algo *ma, struct ctrl_node *cn);

uint32_t update_metric(struct metric_record *mr, struct metric_algo *ma, SQN_T sqn_in, SQN_T sqn_max, uint32_t probe);

void update_link_node(struct link_node *ln, struct dev_node *iif, SQN_T sqn, SQN_T sqn_max, uint8_t sqr, uint32_t probe);

void purge_orig(struct dev_node *only_dev, IDM_T only_expired);
void free_orig_node(struct orig_node *on);

IDM_T update_orig_metrics(struct packet_buff *pb, struct orig_node *on, IID_T orig_sqn);

struct dhash_node* create_dhash_node(struct description_hash *dhash,  struct orig_node *on);
void free_dhash_node( struct dhash_node *dhn );
void invalidate_dhash_node( struct dhash_node *dhn );


IDM_T update_neigh_node(struct link_node *ln, struct dhash_node *dhn, IID_T neighIID4neigh);

IDM_T update_neighIID4x_repository(struct neigh_node *neigh, IID_T neighIID4x, struct dhash_node *dhn);

struct dev_node * get_bif(char *dev);

void rx_packet( struct packet_buff *pb );
/***********************************************************
 Runtime Infrastructure
************************************************************/
void wait_sec_msec( uint32_t sec, uint32_t msec );

void cleanup_all( int status );

void upd_time( struct timeval *precise_tv );

char *get_human_uptime( uint32_t reference );

int32_t rand_num( uint32_t limit );

int8_t terminating();

uint8_t bits_count( uint32_t v );

uint8_t bit_get(uint8_t *array, uint16_t array_bit_size, uint16_t bit);

void bit_set(uint8_t *array, uint16_t array_bit_size, uint16_t bit, IDM_T value);

void bit_clear(uint8_t *array, uint16_t array_bit_size, uint16_t begin, uint16_t end);

void byte_clear(uint8_t *array, uint16_t array_size, uint16_t begin, uint16_t range);

uint8_t is_zero(char *data, int len);


/***********************************************************
 Configuration data and handlers
************************************************************/


IDM_T validate_name( char* name );

int32_t opt_update_description ( uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn );
