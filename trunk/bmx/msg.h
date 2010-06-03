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


#define MIN_UDPD_SIZE 256 //(6+4+(22+8)+32)+184=72+56=128
#define DEF_UDPD_SIZE 512
#define MAX_UDPD_SIZE 1400
#define ARG_UDPD_SIZE "udp_data_size"


#define MIN_AGGREG_INTERVAL 35
#define MAX_AGGREG_INTERVAL 4000
#define DEF_AGGREG_INTERVAL 500
#define ARG_AGGREG_INTERVAL "aggregation_interval"

#define ARG_HELLO_INTERVAL "hello_interval"
#define DEF_HELLO_INTERVAL DEF_OGM_AGGREG_INTERVAL
#define MIN_HELLO_INTERVAL 50
#define MAX_HELLO_INTERVAL 10000
extern int32_t my_hello_interval;


#define ARG_OGM_INTERVAL "ogm_interval"
#define DEF_OGM_INTERVAL 2000
#define MIN_OGM_INTERVAL 200
#define MAX_OGM_INTERVAL 60000
extern int32_t my_ogm_interval;


#define DEF_TX_TS_TREE_SIZE 100
#define DEF_TX_TS_TREE_PURGE_FK 5



#define MIN_OGM_AGGREG_INTERVAL ( MIN_OGM_INTERVAL/10 )
#define MAX_OGM_AGGREG_INTERVAL ( DEF_OGM_INTERVAL/2 )
#define DEF_OGM_AGGREG_INTERVAL ( DEF_OGM_INTERVAL/5 )

#define MAX_OGM_RESEND_INTERVAL (MAX_AGGREG_INTERVAL * 2)
#define DEF_OGM_RESEND_INTERVAL ((DEF_AGGREG_INTERVAL * 2) / 3)

#define MIN_OGM_RESEND_ATTEMPTS 0
#define MAX_OGM_RESEND_ATTEMPTS 5
#define DEF_OGM_RESEND_ATTEMPTS 3
#define ARG_OGM_RESEND_ATTEMPTS "ogm_resend_attempts"

#define MIN_NBDISC_RTQ (PROBE_RANGE / 8)
#define MIN_OGM_ACK_RTQ (PROBE_RANGE / 4)




//TODO: set REQ_TO to 1 (in a non-packet-loss testenvironment this may be set to 1000 for testing)
#define DEF_TX_DESC0_REQ_TO  1000
#define DEF_TX_DESC0_ADV_TO   500
#define DEF_TX_DHASH0_REQ_TO 1000
#define DEF_TX_DHASH0_ADV_TO  500

#define MIN_DESC0_REFERRED_TO 10000
#define MAX_DESC0_REFERRED_TO 100000
#define DEF_DESC0_REFERRED_TO 10000

#define MAX_PKT_MSG_SIZE (MAX_UDPD_SIZE - sizeof(struct packet_header) - sizeof(struct frame_header))

#define MAX_DESC0_TLV_SIZE (MAX_PKT_MSG_SIZE - sizeof(struct msg_description_adv) )



struct packet_header
{
	uint8_t  bmx_version;
	uint8_t  bmx_capabilities;
	uint16_t pkt_length; 		// the relevant data size in bytes (including the bmx_header)
	uint16_t pkt_dev_sqn;
	uint8_t  pkt_data[];            // encapulating packet data tlvs
} __attribute__((packed));


#define FRAME_TYPE_RESERVED0  0
#define FRAME_TYPE_RESERVED1  1
#define FRAME_TYPE_HI40_ADVS  2 // most-simple BMX-NG hello (nb-discovery) advertisements
#define FRAME_TYPE_HI40_REPS  3 // most-simple BMX-NG hello (nb-discovery) replies
#define FRAME_TYPE_HI60_REPS  4 //
#define FRAME_TYPE_RESERVED4  5 // BMX_FRM_CRT0_REQS
#define FRAME_TYPE_RESERVED5  6 // BMX_FRM_CRT0_ADV
#define FRAME_TYPE_DSC0_REQS  7 // ...
#define FRAME_TYPE_DSC0_ADVS  8 // descriptions are send as individual advertisement frames
#define FRAME_TYPE_DHS0_REQS  9 // Hash-for-description-of-OG-ID requests
#define FRAME_TYPE_DHS0_ADVS  10 // Hash-for-description-of-OG-ID advertisements
#define FRAME_TYPE_OGM0_ADVS  11 // most simple BMX-NG (type 0) OGM advertisements
#define FRAME_TYPE_OGM0_ACKS  12 // most simple BMX-NG (type 0) OGM advertisements
#define FRAME_TYPE_NOP        13
#define FRAME_TYPE_ARRSZ      14
#define FRAME_TYPE_MAX        0xFF


/*
 * dhash0_adv or description0_adv specific frame flag
 * firstIsSender flag is usefull to accelerate neighbor (and neighIID) discovery process
 */

#define FRAME_FLAG_firstIsSender 0x01 // first message references transmitter of packet containing this message
#define FRAME_FLAGS_MAX 255


struct frame_header {
	uint8_t  type;    // frame type
	uint8_t  flags;   // frame-type specific (8-bit) value containing flags or other data (e.g. sqn, mark,..)
	uint16_t length;  // lenght of frame including frame_header and variable data field
	uint8_t  data[];  // frame-type specific data consisting of 0-1 data headers and 0-n data messages
} __attribute__((packed));


struct msg_hello_adv {
	SQN_T hello_dev_sqn;
} __attribute__((packed));
/*
 *  reception trigger:
 * - update_link_nodes()
 * - msg_hellp40_reply[]
 *
 */

struct msg_hello_reply {
	IP4_T receiver_ip4;
	SQN_T hello_dev_sqn;
} __attribute__((packed));
/*
 * reception triggers:
 * - update_link_nodes()
 * - (if NOT link->neigh->dhash->orig) msg_dhash0_request[ ... orig_did = IID_RSVD_4YOU ]
 *
 */


/*
struct hdr_dhash_request {
	IP4_T receiver_ip4;
} __attribute__((packed));
*/
struct msg_dhash_request {
	IP4_T receiver_ip4;  // dest_llip4;
	IID_T receiverIID4x; //(orig_did) IID_RSVD_4YOU to ask for neighbours' dhash0
} __attribute__((packed));
/*
 * reception triggers:
 * - msg_dhash0_adv[ ]
 *
 */


struct msg_dhash_adv {
	IID_T transmitterIID4x;  //orig_sid
	struct description_hash dhash;
} __attribute__((packed));
/*
 * reception triggers:
 * - (if description is known AND is neighbor) creation of link <-> neigh <-> dhash <-> orig <-> description
 * - (else if description is known ) creation of dhash <-> orig <-> description
 * - (else) msg_description0_request[]
 */


struct msg_description_request {
	IP4_T receiver_ip4;
	IID_T receiverIID4x; //(orig_did) IID_RSVD_4YOU to ask for neighbours' description0
} __attribute__((packed));
/*
 * reception triggers:
 * - msg_description0_adv[]
 *
 */



struct description {
	struct description_id id;

	uint16_t dsc_tlvs_len;
	SQN_T dsc_sqn;

	SQN_T ogm_sqn_min;
	SQN_T ogm_sqn_range;
	uint8_t ogm_sqn_pq_bits;
	uint8_t dsc_rsvd;

	uint16_t path_ogi;

	uint16_t path_window_size;
	uint16_t path_lounge_size;

	uint8_t path_hystere;
	uint8_t ttl_max;

	uint8_t hop_penalty;
	uint8_t late_penalty;
	uint8_t asym_weight;
	uint8_t sym_weight;

	uint16_t rsvd_u16;
	uint32_t reserved[2]; //ensure traditional message size

//	uint8_t tlv_frames[];
} __attribute__((packed));


#define MSG_DESCRIPTION0_ADV_UNHASHED_SIZE  6
#define MSG_DESCRIPTION0_ADV_HASHED_SIZE   (sizeof( struct description_id) + (8 * 4))
#define MSG_DESCRIPTION0_ADV_SIZE  (MSG_DESCRIPTION0_ADV_UNHASHED_SIZE + MSG_DESCRIPTION0_ADV_HASHED_SIZE)

struct msg_description_adv {
	
	// the unhashed part:
	IID_T    transmitterIID4x; // orig_sid
	uint8_t  ttl;
	uint8_t  reserved0;
	uint16_t reserved1;

	// the hashed pard:
	struct description desc;

} __attribute__((packed));
/*
 * reception triggers:
 * - creation of dhash_node <-> description_node
 *
 */

#define MAX_OGMS_PER_AGGREG ( MIN((FRAME_FLAGS_MAX-1),((MIN_UDPD_SIZE - (sizeof(struct packet_header) + sizeof(struct frame_header))) / sizeof(struct msg_ogm_adv))) )
#define MIN_OGMS_PER_AGGREG ( MAX_OGMS_PER_AGGREG  / 8 )
#define DEF_OGMS_PER_AGGREG ( MAX_OGMS_PER_AGGREG  / 2 )

//struct msg_ogm0_adv;

struct msg_ogm_adv {
	IID_T  	 transmitterIID4x;  //orig_sid
	SQN_T 	 orig_sqn;
} __attribute__((packed));

struct hdr_ogm_adv {
	SQN_T aggregation_sqn;
	struct msg_ogm_adv msg[];
} __attribute__((packed));

/*
 * reception triggers:
 * - (if link <-> neigh <-... is known and orig_sid is NOT known) msg_dhash0_request[ ... orig_did = orig_sid ]
 * - else update_orig(orig_sid, orig_sqn)
 */

struct msg_ogm_ack {
//	IID_T transmitterIID4receiver;
	IP4_T receiver_ip4;
	SQN_T aggregation_sqn;
} __attribute__((packed));
/*
 * reception triggers:
 * - (if link <-> neigh <-... is known and orig_sid is NOT known) msg_dhash0_request[ ... orig_did = orig_sid ]
 * - else update_orig(orig_sid, orig_sqn)
 */





#define BMX_DSC_TLV_GLIP4 0x00
#define BMX_DSC_TLV_UHNA4 0x01
#define BMX_DSC_TLV_ARRSZ 0x02
#define BMX_DSC_TLV_MAX   0xFF

#define TLVS_SUCCESS SUCCESS
#define TLVS_FAILURE FAILURE
#define TLVS_BLOCKED 1

enum {
	TLV_DEL_TEST_ADD = 0,
	TLV_TEST = 1,
	TLV_ADD = 2,
	TLV_DONE = 3,
	TLV_DEBUG = 4
};


struct description0_msg_ip4 {
	IP4_T    ip4;
} __attribute__((packed));

struct description0_msg_hna4 {
	uint8_t prefix_len;
	uint8_t reserved;
	IP4_T    ip4;
	uint32_t metric;
} __attribute__((packed));






struct description_cache_node {
	struct description_hash dhash;
        uint32_t timestamp;
        struct description *description;
};

#define DEF_DESC0_CACHE_SIZE 3
#define DEF_DESC0_CACHE_TO   100000

#define DEF_UNSOLICITED_DESCRIPTIONS YES


extern char *tlv_op_str[];

extern uint32_t ogm_aggreg_pending;

/***********************************************************
  The core frame/message structures and handlers
************************************************************/

void update_my_description_adv( void );

void purge_tx_timestamp_tree(struct dev_node *dev, IDM_T purge_all);
void purge_dev_tx_list( struct dev_node *dev );

void tx_packet( void* dev_node );

int rx_frames(struct packet_buff *pb, uint8_t* fdata, uint16_t fsize);

void schedule_my_hello_message( void* dev_node );

IDM_T process_description_tlvs(struct orig_node *on, struct description *dsc_new, IDM_T op, struct ctrl_node *cn);

void init_msg( void );

void cleanup_msg( void );


