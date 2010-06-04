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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <errno.h>


//#include <sha.h>

#include "bmx.h"
#include "msg.h"
#include "hna.h"
#include "schedule.h"


static Sha bmx_sha;

AVL_TREE( description_cache_tree, struct description_cache_node, dhash );



static int32_t max_udpd_size = DEF_UDPD_SIZE;

static int32_t aggreg_interval = DEF_AGGREG_INTERVAL;

int32_t my_ogm_interval = DEF_OGM_INTERVAL;   /* orginator message interval in miliseconds */

int32_t my_hello_interval = DEF_HELLO_INTERVAL;

int32_t ogm_resend_attempts = DEF_OGM_RESEND_ATTEMPTS;

int my_desc0_tlv_len = 0;

IID_T myIID4me = IID_RSVD_UNUSED;


LIST_SIMPEL( ogm_aggreg_list, struct ogm_aggreg_node, list );
uint32_t ogm_aggreg_pending = 0;
static SQN_T ogm_aggreg_sqn_max;


char *tlv_op_str[] = {"TLV_DEL","TLV_TEST","TLV_ADD","TLV_DONE","TLV_DEBUG"};




STATIC_FUNC int tx_msg_hello40_reply                  (struct tx_task_node *ttn, uint8_t *flags, uint8_t *tx_buff, uint16_t buff_size);
STATIC_FUNC int tx_msg_helloX0_adv                    (struct tx_task_node *ttn, uint8_t *flags, uint8_t *tx_buff, uint16_t buff_size);
STATIC_FUNC int tx_msg_description0_adv               (struct tx_task_node *ttn, uint8_t *flags, uint8_t *tx_buff, uint16_t buff_size);

STATIC_FUNC int tx_msg_dhash0_adv                     (struct tx_task_node *ttn, uint8_t *flags, uint8_t *tx_buff, uint16_t buff_size);

STATIC_FUNC int tx_msg_dhash0_or_description0_request (struct tx_task_node *ttn, uint8_t *flags, uint8_t *tx_buff, uint16_t buff_size);
STATIC_FUNC int tx_msg_ogm_ack                        (struct tx_task_node *ttn, uint8_t *flags, uint8_t *tx_buff, uint16_t buff_size);

STATIC_FUNC int tx_frame_ogm0_advs   (struct tx_task_node *ttn, uint8_t *flags, uint8_t *tx_buff, uint16_t buff_size);


STATIC_FUNC int rx_frame_hello40_replies                 (struct packet_buff *pb, struct frame_header *frame);
STATIC_FUNC int rx_frame_helloX0_advs                    (struct packet_buff *pb, struct frame_header *frame);
STATIC_FUNC int rx_frame_description0_advs               (struct packet_buff *pb, struct frame_header *frame);

STATIC_FUNC int rx_frame_dhash0_advs                     (struct packet_buff *pb, struct frame_header *frame);

STATIC_FUNC int rx_frame_dhash0_or_description0_requests (struct packet_buff *pb, struct frame_header *frame);

STATIC_FUNC int rx_frame_ogm0_advs                       (struct packet_buff *pb, struct frame_header *frame);
STATIC_FUNC int rx_frame_ogm40_acks                      (struct packet_buff *pb, struct frame_header *frame);

/***********************************************************
  The core frame/message structures and handlers
 ************************************************************/



struct description_tlv_handler {
        uint16_t reserved1;
        uint16_t reserved2;
        uint16_t min_msg_size;
        uint16_t variable_msg_size;
        char *name;
        int (*create_tlv) (uint8_t *data, uint16_t max_size);
        int (*process_tlv) (struct orig_node *on, struct frame_header *tlv, IDM_T op, struct ctrl_node *cn);
};

struct description_tlv_handler description0_tlv_handler[BMX_DSC_TLV_MAX] = {
        {0, 0, sizeof (struct description0_msg_ip4), 0,
                "desc0tlv_glip4", create_description_tlv_ip4, process_description_tlv_hna4}
        ,
        {0, 0, sizeof (struct description0_msg_hna4), 0,
                "desc0tlv_uhna4", create_description_tlv_hna4, process_description_tlv_hna4}
};



struct pkt_frame_handler {
        uint16_t reserved;
        uint16_t tx_iterations;
        uint16_t min_rtq;
        uint16_t data_header_size;
        uint16_t min_msg_size;
        uint16_t fixed_msg_size;
        uint32_t min_tx_interval;
        char *name;
        int (*tx_frm_creator) (struct tx_task_node * ttn, uint8_t *flags, uint8_t *tx_buff, uint16_t buff_size);
/*
 * tx_msg_creator()
 * expects sufficient buff_size for non-variable_msg_size messages !!!
 * returns x=sizeof(send msg), thus (x<=buff_size), if msg was successfully created
 * returns (x > buff_size) if variable_msg_size could not be created due to lack of buff_size
 * returns 0 if message MUST be send later
 * returns FAILRUE if porblem occured and msg-meta data (tx_task_node) MUST be destroyed
 */
        int (*tx_msg_creator) (struct tx_task_node * ttn, uint8_t *flags, uint8_t *tx_buff, uint16_t buff_size);
        int (*rx_frm_receptor) (struct packet_buff *, struct frame_header *);
};


static struct pkt_frame_handler frame_handler[FRAME_TYPE_ARRSZ] = {
        {0, 0, 0, 0, 0, 1, 0, NULL, NULL, NULL, NULL},
        {0, 0, 0, 0, 0, 1, 0, NULL, NULL, NULL, NULL},

        {0, 1, 0, 0, sizeof (struct msg_hello_adv), 1, 0,
                "hey0_adv", NULL, tx_msg_helloX0_adv, rx_frame_helloX0_advs},

        {0, 1, 0, 0, sizeof (struct msg_hello_reply), 1, 0,
                "hey0_rep", NULL, tx_msg_hello40_reply, rx_frame_hello40_replies},
        {0, 0, 0, 0, 0, 1, 0, NULL, NULL, NULL, NULL},

        {0, 0, 1, 0, 0, 1, 0, NULL, NULL, NULL, NULL},
        {0, 0, 1, 0, 0, 1, 0, NULL, NULL, NULL, NULL},

        {0, 1, MIN_NBDISC_RTQ, 0, sizeof (struct msg_description_request), 1, DEF_TX_DESC0_REQ_TO, // receiverIID, receiverIP4
                "desc0_req", NULL, tx_msg_dhash0_or_description0_request, rx_frame_dhash0_or_description0_requests},

        {0, 1, MIN_NBDISC_RTQ, 0, sizeof (struct msg_description_adv), 0, DEF_TX_DESC0_ADV_TO,  // myIID4x
                "desc0_adv", NULL, tx_msg_description0_adv, rx_frame_description0_advs},

        {0, 1, MIN_NBDISC_RTQ, 0, sizeof (struct msg_dhash_request), 1, DEF_TX_DHASH0_REQ_TO, // receiverIID, receiverIP4
                "dhash0_req", NULL, tx_msg_dhash0_or_description0_request, rx_frame_dhash0_or_description0_requests},

        {0, 1, MIN_NBDISC_RTQ, 0, sizeof (struct msg_dhash_adv), 1, DEF_TX_DHASH0_ADV_TO, // myIID4x
                "dhash_adv", NULL, tx_msg_dhash0_adv, rx_frame_dhash0_advs},

        {0, 1, 0, sizeof (struct hdr_ogm_adv), sizeof (struct msg_ogm_adv), 1, 0,
                "ogm_adv", tx_frame_ogm0_advs, NULL, rx_frame_ogm0_advs},

        {0, 2, 0, 0, sizeof (struct msg_ogm_ack), 1, 0,
                "ogm_ack", NULL, tx_msg_ogm_ack, rx_frame_ogm40_acks},

        {0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL}

};




STATIC_FUNC
struct description * rem_cached_description(struct description_hash *dhash)
{
        struct description_cache_node *dcn;

        if (!(dcn = avl_find_item(&description_cache_tree, dhash)))
                return NULL;

        struct description *desc0 = dcn->description;

        avl_remove(&description_cache_tree, &dcn->dhash, -300206);
        debugFree(dcn, -300108);

        return desc0;
}

STATIC_FUNC
struct description_cache_node *purge_cached_descriptions( IDM_T purge_all ) {

        struct description_cache_node *dcn;
        struct description_cache_node *dcn_min = NULL;
        struct description_hash tmp_dhash;
        memset( &tmp_dhash, 0, sizeof(struct description_hash));

        dbgf_all( DBGT_INFO, "%s", purge_all ? "purge_all" : "only_expired");

        paranoia( -500349, (!is_zero((char*)&tmp_dhash, BMX_HASH0_LEN)));

        while ((dcn = avl_next_item(&description_cache_tree, &tmp_dhash))) {

                memcpy(&tmp_dhash, &dcn->dhash, BMX_HASH0_LEN);

                if (purge_all || ((uint32_t) (bmx_time - dcn->timestamp)) > DEF_DESC0_CACHE_TO) {

                        avl_remove(&description_cache_tree, &dcn->dhash, -300208);
                        debugFree(dcn->description, -300100);
                        debugFree(dcn, -300101);

                } else {

                        if (!dcn_min || LESS_U32(dcn->timestamp, dcn_min->timestamp))
                                dcn_min = dcn;
                }
        }

        return dcn_min;
}

STATIC_FUNC
void cache_description(struct description *desc, struct description_hash *dhash)
{
        struct description_cache_node *dcn;

        uint16_t desc_len = sizeof (struct description) + ntohs(desc->dsc_tlvs_len);

        if ((dcn = avl_find_item(&description_cache_tree, dhash))) {
                dcn->timestamp = bmx_time;
                return;
        }

        dbgf_all( DBGT_INFO, "%8X..", dhash->h.u32[0]);


        paranoia(-500261, (description_cache_tree.items > DEF_DESC0_CACHE_SIZE));

        if ( description_cache_tree.items == DEF_DESC0_CACHE_SIZE ) {


                struct description_cache_node *dcn_min = purge_cached_descriptions( NO );

                dbgf(DBGL_SYS, DBGT_WARN, "desc0_cache_tree reached %d items! cleaned up %d items!",
                        DEF_DESC0_CACHE_SIZE, DEF_DESC0_CACHE_SIZE - description_cache_tree.items);

                if (description_cache_tree.items == DEF_DESC0_CACHE_SIZE) {
                        avl_remove(&description_cache_tree, &dcn_min->dhash, -300209);
                        debugFree(dcn_min->description, -300102);
                        debugFree(dcn_min, -300103);
                }
        }

        paranoia(-500273, (desc_len != sizeof ( struct description) + ntohs(desc->dsc_tlvs_len)));

        dcn = debugMalloc(sizeof ( struct description_cache_node), -300104);
        dcn->description = debugMalloc(desc_len, -300105);
        memcpy(dcn->description, desc, desc_len);
        memcpy( &dcn->dhash, dhash, BMX_HASH0_LEN );
        dcn->timestamp = bmx_time;
        avl_insert(&description_cache_tree, dcn, -300145);

}

void purge_tx_timestamp_tree(struct dev_node *dev, IDM_T purge_all)
{
        struct avl_node *an;
        struct tx_timestamp_node *ttn = NULL;
        struct tx_timestamp_key key;

        memset(&key, 0, sizeof (struct tx_timestamp_key));

        dbgf_all( DBGT_INFO, "%s %s", dev->name, purge_all ? "purge_all" : "only_expired");

        while ((an = avl_next(&dev->tx_timestamp_tree, (ttn ? &ttn->key : &key)))) {

                ttn = an->item;

                if (purge_all || ((uint32_t) (bmx_time - ttn->timestamp)) >
                        (DEF_TX_TS_TREE_PURGE_FK * frame_handler[ttn->key.type].min_tx_interval)) {

                        memcpy( &key, &ttn->key, sizeof( struct tx_timestamp_key ) );

                        avl_remove( &dev->tx_timestamp_tree, &ttn->key, -300210 );
                        debugFree( ttn, -300127 );
                        ttn = NULL;
                }
        }
}


STATIC_FUNC
struct tx_timestamp_node * tx_timestamp_add( struct dev_node *dev, struct tx_timestamp_key *key)
{
        ASSERTION( -500263, ( dev && !avl_find( &dev->tx_timestamp_tree, key ) ) );

        if (dev->tx_timestamp_tree.items > DEF_TX_TS_TREE_SIZE) {

                purge_tx_timestamp_tree(dev, NO);

                if (dev->tx_timestamp_tree.items > DEF_TX_TS_TREE_SIZE) {
                        dbg_mute(20, DBGL_SYS, DBGT_WARN, "%s tx_ts_tree reached %d %s neighIID4x %u %s %u",
                                dev->name, dev->tx_timestamp_tree.items, frame_handler[key->type].name,
                                key->neighIID4x, ipStr(key->myIID4x_or_dest_ip4), key->myIID4x_or_dest_ip4);
                }
        }

        struct tx_timestamp_node *ttn = debugMalloc(sizeof ( struct tx_timestamp_node), -300126);
        memset(ttn, 0, sizeof ( struct tx_timestamp_node));
        memcpy( &ttn->key, key, sizeof(struct tx_timestamp_key ) );
        ttn->timestamp = bmx_time;
        avl_insert(&dev->tx_timestamp_tree, ttn, -300146);

        return ttn;
}

STATIC_FUNC
IDM_T tx_task_obsolete( struct dev_node *dev, uint8_t frame_type, struct tx_task_node *tx_task )
{
        struct tx_timestamp_node *ttn = NULL;
        struct tx_timestamp_key key;
        struct dhash_node *dhn = NULL;

        if (tx_task->myIID4x >= IID_MIN_USED && !((dhn = iid_get_node_by_myIID4x(tx_task->myIID4x)) && dhn->on)) {
                goto tx_timestamped_deny;
        }

        if (!frame_handler[frame_type].min_tx_interval)
                return NO;

        memset(&key, 0, sizeof (struct tx_timestamp_key));

        key.myIID4x_or_dest_ip4 = tx_task->myIID4x ? tx_task->myIID4x : tx_task->dst_ip4;
        key.neighIID4x = tx_task->neighIID4x;
        key.type = frame_type;

        if (frame_handler[frame_type].min_tx_interval && (ttn = avl_find_item(&dev->tx_timestamp_tree, &key))) {

                if (((uint32_t) (bmx_time - ttn->timestamp) < frame_handler[frame_type].min_tx_interval)) {

                        goto tx_timestamped_deny;
                }

                ttn->timestamp = bmx_time;
        }

        if (!ttn)
                ttn = tx_timestamp_add(dev, &key);

        return NO;


tx_timestamped_deny:
        dbgf(DBGL_CHANGES, DBGT_WARN,
                "skipping %s %s myIId4x %d neighIID4x %d %s %s send just %d ms ago",
                frame_handler[frame_type].name, dev->name,
                tx_task->myIID4x, tx_task->neighIID4x, ipStr(tx_task->dst_ip4),
                dhn ? dhn->on->id.name : "???",
                ttn ? (int)(bmx_time - ttn->timestamp) : -1);

        return YES;
}




STATIC_FUNC
IDM_T validate_param(int32_t probe, int32_t min, int32_t max, char *name, struct opt_type *opt)
{
        if (opt) {
                min = opt->imin;
                max = opt->imax;
                name = opt->long_name;
        }

        if ( probe < min || probe > max ) {

                dbgf( DBGL_SYS, DBGT_ERR, "Illegal %s parameter value %d ( min %d  max %d )",
                        name, probe, min, max);

                return FAILURE;
        }

        return SUCCESS;
}





IDM_T process_description_tlvs(struct orig_node *on, struct description *desc_new, IDM_T op, struct ctrl_node *cn)
{
        struct description *desc;
        IDM_T tlv_result;
        uint16_t pos = 0, t = 0, pt = 0, size = 0, tlv_size = 0;
        struct frame_header * tlv = NULL;

        assertion(-500370, (op == TLV_DEL_TEST_ADD || op == TLV_DEBUG));

        desc = on->desc0; //start with removing the old desc0_tlvs

        do {
                if (op == TLV_TEST || op == TLV_ADD)
                        desc = desc_new;

                if (!desc || (op == TLV_DEL_TEST_ADD && on->blocked))
                        continue;


                dbgf_all( DBGT_INFO, "%s %s dsc_sqn %d size %d ",
                        tlv_op_str[op], desc->id.name, ntohs(desc->dsc_sqn), ntohs(desc->dsc_tlvs_len));


                size = ntohs(desc->dsc_tlvs_len);
                tlv = NULL;
                pos = t = pt = 0;


                assertion(-500274, (size <= MAX_DESC0_TLV_SIZE)); // checked in rx_frm_desc0_advs()

                while (pos + sizeof ( struct frame_header) < size) {

                        tlv = (struct frame_header*) (((char*) desc) + sizeof (struct description) + pos);
                        tlv_size = ntohs(tlv->length);

                        if ((t = tlv->type) < pt ||
                                tlv_size < sizeof ( struct frame_header) ||
                                tlv_size + pos > size) {

                                dbgf(DBGL_SYS, DBGT_ERR,
                                        "illegal sizes %d for type %s", tlv_size, description0_tlv_handler[t].name);
                                goto process_desc0_tlv_error;
                        }

                        dbgf(DBGL_ALL, DBGT_INFO,
                                "type %s  size %d flags 0x%X", description0_tlv_handler[t].name, tlv_size, tlv->flags);


                        if (t >= BMX_DSC_TLV_ARRSZ || !(description0_tlv_handler[t].process_tlv)) {

                                dbgf(DBGL_SYS, DBGT_WARN,
                                        "unsupported type %d ! maybe you need an update?", t);

                                if (t >= BMX_DSC_TLV_ARRSZ)
                                        goto process_desc0_tlv_error;

                        } else if (tlv_size - sizeof (struct frame_header) < description0_tlv_handler[t].min_msg_size) {

                                dbgf(DBGL_SYS, DBGT_ERR,
                                        "too small size %d for type %s", tlv_size, description0_tlv_handler[t].name);
                                goto process_desc0_tlv_error;

                        } else if (!(description0_tlv_handler[t].variable_msg_size) &&
                                (tlv_size - sizeof (struct frame_header)) % description0_tlv_handler[t].min_msg_size) {

                                dbgf(DBGL_SYS, DBGT_ERR,
                                        "nonmaching size %d for type %s", tlv_size, description0_tlv_handler[t].name);
                                goto process_desc0_tlv_error;

                        } else if ((tlv_result = (*(description0_tlv_handler[t].process_tlv)) (on, tlv, op, cn)) != TLVS_SUCCESS) {

                                assertion(-500356, (op == TLV_TEST));

                                dbgf(DBGL_SYS, DBGT_ERR,
                                        "%s size %d  %s", description0_tlv_handler[t].name, tlv_size,
                                        tlv_result == TLVS_BLOCKED ? "BLOCKED" : "FAILURE");

                                if (tlv_result == TLVS_BLOCKED) {

                                        on->blocked = YES;

                                        if (!avl_find(&blocked_tree, &on->id))
                                                avl_insert(&blocked_tree, on, -300165);

                                        return TLVS_BLOCKED;
                                }

                                goto process_desc0_tlv_msg_error;
                        }

                        pt = t;
                        pos += tlv_size;
                }

                if (pos != size) {
                        dbgf(DBGL_SYS, DBGT_ERR, "nonmaching tlvs pos %d != size %d", pos, size );

                        goto process_desc0_tlv_error;
                }

        } while (++op < TLV_DONE);

        if ( op == TLV_DONE ) {
                on->blocked = NO;
                avl_remove(&blocked_tree, &on->id, -300211);
        }
        
        return SUCCESS;


process_desc0_tlv_msg_error:
        dbgf(DBGL_SYS, DBGT_WARN,
                "rcvd problematic message");

process_desc0_tlv_error:
        dbgf(DBGL_SYS, DBGT_WARN,
                "rcvd problematic frame type %s last %s  frm_size %d  pos %d ",
                description0_tlv_handler[t].name, description0_tlv_handler[pt].name, tlv_size, pos);

        return TLVS_FAILURE;
}

//BMX3 (done)
struct dhash_node * process_description(struct packet_buff *pb, struct description *desc, struct description_hash *dhash)
{
        assertion(-500262, (pb && pb->ln && desc));
        assertion(-500381, (!avl_find( &dhash_tree, dhash )));

        struct dhash_node *dhn;
        struct orig_node *on = NULL;
        int id_name_len;


        dbgf_all(  DBGT_INFO, "via dev: %s NB %s:dhash %8X.. id.rand %jX",
                pb->iif->name, pb->neigh_str, dhash->h.u32[0], desc->id.rand.u64[0]);

        if (
                (id_name_len = strlen(desc->id.name)) >= DESCRIPTION0_ID_NAME_LEN ||
                !is_zero(&desc->id.name[id_name_len], DESCRIPTION0_ID_NAME_LEN - id_name_len) ||
                validate_name(desc->id.name) == FAILURE) {

                dbg(DBGL_SYS, DBGT_ERR, "illegal hostname .. %jX", desc->id.rand.u64[0]);
                goto process_desc0_error;
        }

        if (
                validate_param(ntohs(desc->ogm_sqn_range), MIN_OGM0_SQN_RANGE, MAX_OGM0_SQN_RANGE, ARG_OGM0_SQN_RANGE, NULL) ||
                validate_param(desc->ogm_sqn_pq_bits, MIN_OGM0_PQ_BITS, MAX_OGM0_PQ_BITS, ARG_OGM0_PQ_BITS, NULL) ||
                validate_param(ntohs(desc->path_ogi), 0, 0, NULL, get_option(0, 0, ARG_OGM_INTERVAL)) ||
                validate_param(desc->ttl_max, 0, 0, NULL, get_option(0, 0, ARG_TTL)) ||
                validate_param(ntohs(desc->path_window_size), 0, 0, NULL, get_option(0, 0, ARG_PWS)) ||
                validate_param(ntohs(desc->path_lounge_size), 0, 0, NULL, get_option(0, 0, ARG_PATH_LOUNGE)) ||
                validate_param(desc->path_hystere, 0, 0, NULL, get_option(0, 0, ARG_PATH_HYST)) ||
//                validate_param(dsc->hop_penalty, 0, 0, NULL, get_option(0, 0, ARG_HOP_PENALTY)) ||
                validate_param(desc->late_penalty, 0, 0, NULL, get_option(0, 0, ARG_LATE_PENAL)) ||
                validate_param(desc->asym_weight, 0, 0, NULL, get_option(0, 0, ARG_ASYM_WEIGHT)) ||
//                validate_param(dsc->sym_weight, 0, 0, NULL, get_option(0, 0, ARG_SYM_WEIGHT)) ||
                0
                ) {

                goto process_desc0_error;
        }


        if ((on = avl_find_item(&orig_tree, &desc->id))) {

                assertion(-500383, (on->dhn));

                if (((uint32_t) (bmx_time - on->dhn->referred_timestamp)) < (uint32_t) dad_to) {

                        if ( ((SQN_T)(ntohs(desc->dsc_sqn) - (on->desc0_sqn + 1))) >  SQN_DAD_RANGE ) {

                                dbgf(DBGL_SYS, DBGT_ERR, "DAD-Alert: new dsc_sqn %d not > old %d + 1",
                                        ntohs(desc->dsc_sqn), on->desc0_sqn);

                                goto process_desc0_ignore;
                        }

                        if (LESS_SQN(ntohs(desc->ogm_sqn_min), (on->ogm_sqn_min + MAX_OGM0_SQN_RANGE))) {

                                dbgf(DBGL_SYS, DBGT_ERR, "DAD-Alert: new ogm_sqn_min %d not > old %d + %d",
                                        ntohs(desc->ogm_sqn_min), on->ogm_sqn_min, MAX_OGM0_SQN_RANGE);

                                goto process_desc0_ignore;
                        }
                }


        } else {
                // create new orig:
                on = debugMalloc( sizeof( struct orig_node ), -300128 );
                memset( on, 0, sizeof( struct orig_node ) );
                memcpy(&on->id, &desc->id, sizeof ( struct description_id));
/*
                on->id.rand.u32[0] = ntohl( desc->id.rand.u32[0] );
                on->id.rand.u32[1] = ntohl( desc->id.rand.u32[1] );
*/
                AVL_INIT_TREE(on->router_tree, struct router_node, key );
                avl_insert(&orig_tree, on, -300148);
        }

        dbgf_all( DBGT_INFO, "rcvd new desc SQN %d (old %d) from %s via %s NB %s",
                ntohs(desc->dsc_sqn), on->desc0_sqn, desc->id.name, pb->iif->name, pb->neigh_str);

        if (process_description_tlvs(on, desc, TLV_DEL_TEST_ADD, NULL) == TLVS_FAILURE)
                goto process_desc0_error;

        // might result in TLVS_BLOCKED !!


        on->updated_timestamp = bmx_time;
        on->desc0_sqn = ntohs(desc->dsc_sqn);

        on->ogm_sqn_min = ntohs(desc->ogm_sqn_min);
        on->ogm_sqn_range = ntohs(desc->ogm_sqn_range);
        on->ogm_sqn_pq_bits = desc->ogm_sqn_pq_bits;

//        on->ogm_sqn_mask = (MAX_SQN << on->ogm_sqn_pq_bits);
//        on->ogm_sqn_steps = (0x01 << on->ogm_sqn_pq_bits);


        struct metric_algo test_algo;
        memset(&test_algo, 0, sizeof (struct metric_algo));

        test_algo.sqn_mask = (MAX_SQN << on->ogm_sqn_pq_bits);
        test_algo.sqn_steps = (0x01 << on->ogm_sqn_pq_bits);
        test_algo.regression = ntohs(desc->path_window_size) / test_algo.sqn_steps / 2;
        test_algo.sqn_lounge = ntohs(desc->path_lounge_size);
        test_algo.sqn_window = ntohs(desc->path_window_size);
        test_algo.metric_max = PROBE_RANGE;


        if ( validate_metric_algo( &test_algo, NULL ) == FAILURE )
                goto process_desc0_error;

        memcpy(&on->path_metric_algo, &test_algo, sizeof (struct metric_algo));

        on->ogm_sqn_max_rcvd = on->ogm_sqn_aggregated = on->ogm_sqn_to_be_send = (on->ogm_sqn_min & on->path_metric_algo.sqn_mask);


        // migrate current router_nodes->mr.clr position to new sqn_range:
        struct router_node *rn;
        struct avl_node *an;
        for (an = NULL; (rn = avl_iterate_item(&on->router_tree, &an));)
                rn->mr.clr = on->ogm_sqn_max_rcvd /*- on->path_metric_algo.sqn_steps*/;


        if (on->desc0)
                debugFree(on->desc0, -300111);

        on->desc0 = desc;
        desc = NULL;

        struct neigh_node *dhn_neigh = NULL;

        if (on->dhn) {
                dhn_neigh = on->dhn->neigh;
                on->dhn->neigh = NULL;
                on->dhn->on = NULL;
                invalidate_dhash_node(on->dhn);
        }
        
        on->dhn = dhn = create_dhash_node(dhash, on);

        if ( dhn_neigh ) {
                dhn_neigh->dhn = dhn;
                dhn->neigh = dhn_neigh;
        }

        assertion(-500309, (dhn == avl_find_item(&dhash_tree, &dhn->dhash) && dhn->on == on));

        assertion(-500310, (on == avl_find_item(&orig_tree, &on->desc0->id) && on->dhn == dhn));

        return dhn;

process_desc0_error:

        if (on)
                free_orig_node(on);

        blacklist_neighbor(pb);

process_desc0_ignore:

        dbgf(DBGL_SYS, DBGT_WARN, "%jX rcvd via %s NB %s", desc ? desc->id.rand.u64[0] : 0, pb->iif->name, pb->neigh_str);

        if (desc)
                debugFree(desc, -300109);
        
        return NULL;
}

IDM_T freed_tx_task_node(struct tx_task_node *ttn, int tx_creator_result, struct list_node *lprev)
{

        assertion( -500372, (ttn && (ttn)->dev ));

        if (tx_creator_result != ((int) ((ttn)->frame_data_length_target))) {

                dbgf_all( DBGT_WARN, "msg %s to %s via %s   mid4o %d  send_data %d != target_data %d ",
                        frame_handler[(ttn)->frame_type].name,
                        ipStr((ttn)->dst_ip4),
                        (ttn)->dev->name,
                        (ttn)->myIID4x,
                        tx_creator_result,
                        (ttn)->frame_data_length_target);
        }

        if ((--((ttn)->tx_iterations)) == 0) {

                (ttn)->dev->tx_frames_data_len_target -= (ttn)->frame_data_length_target;

                if (lprev)
                        list_del_next(&((ttn)->dev->tx_tasks_list[(ttn)->frame_type]), lprev);
                else
                        (ttn)->dev->my_tx_tasks[(ttn)->frame_type] = NULL;

                debugFree((ttn), -300169);

                return YES;
        }

        (ttn)->tx_timestamp = bmx_time;

        return NO;
}


void schedule_tx_task(struct dev_node *dev_out, struct link_dev_node *lndev_out,
        uint16_t frame_type, uint16_t frame_data_len, SQN_T sqn, IID_T myIID4x, IID_T neighIID4x)
{
        struct tx_task_node *ttn;
        IP4_T dest_ip4 = lndev_out && lndev_out->link ? lndev_out->link->llip4 : 0;

//        struct link_node *ln_out = lndev_out ? lndev_out->link : NULL;

        dbgf_all( DBGT_INFO, "%s %s %s  sqn %d myIID4x %d neighIID4x %d",
                frame_handler[frame_type].name, ipStr(dest_ip4), dev_out->name, sqn, myIID4x, neighIID4x);

        if (frame_handler[ frame_type ].min_rtq > (lndev_out ? lndev_out->mr[SQR_RTQ].val : 0)) {
                return;
        }

        assertion(-500380, (myIID4x != myIID4me)); // should have been translated to IID_RSVD_4YOU by calling function

        assertion(-500433, (frame_handler[frame_type].tx_iterations));

        if (myIID4x == IID_RSVD_4YOU) {

                if ((ttn = dev_out->my_tx_tasks[frame_type])) {

                        dbgf(DBGL_CHANGES, DBGT_WARN, "my_tx_task for %s %s myIID4x %d neighIID4x %d dst %s NOT NULL",
                                frame_handler[frame_type].name, dev_out->name, myIID4x, neighIID4x, ipStr(dest_ip4));

                        assertion(-500442, (ttn->myIID4x == IID_RSVD_4YOU));

                        dev_out->tx_frames_data_len_target -= ttn->frame_data_length_target;

                } else {
                        ttn = dev_out->my_tx_tasks[frame_type] = debugMalloc(sizeof ( struct tx_task_node), -300026);
                }

        } else {

                ttn = debugMalloc(sizeof ( struct tx_task_node), -300026);
                list_add_tail(&(dev_out->tx_tasks_list[frame_type]), &ttn->list);
        }

        ttn->sqn = sqn;
        ttn->dst_ip4 = dest_ip4;
        ttn->myIID4x = myIID4x;
        ttn->neighIID4x = neighIID4x;
        ttn->frame_type = frame_type;
        ttn->tx_iterations = frame_handler[frame_type].tx_iterations;
        ttn->tx_timestamp = bmx_time - 1;
        ttn->dev = dev_out;

        if (!frame_data_len && frame_handler[frame_type].fixed_msg_size && !frame_handler[frame_type].data_header_size) {

                ttn->frame_data_length_target = frame_handler[ frame_type ].min_msg_size;

        } else {

                assertion( -500371, (frame_data_len));

                ttn->frame_data_length_target = frame_data_len;
        }

        dev_out->tx_frames_data_len_target += ttn->frame_data_length_target;


        uint16_t estimated_packet_len =
                (sizeof (struct packet_header)) +
                (sizeof (struct frame_header) * FRAME_TYPE_ARRSZ) +
                (dev_out->tx_frames_data_len_target) +
                (sizeof (struct msg_ogm_adv) * ogm_aggreg_pending);


        if (estimated_packet_len > max_udpd_size) {
                remove_task(tx_packet, dev_out);
                register_task(1, tx_packet, dev_out);
        }


}




void purge_dev_tx_list( struct dev_node *dev ) {
        int i;

        paranoia( -500203, !dev );

        for (i = 0; i < FRAME_TYPE_ARRSZ; i++) {

                struct tx_task_node * dtn;

                while ((dtn=list_rem_head( &(dev->tx_tasks_list[i]) ) ))
                        debugFree(dtn, -300066);

                if ((dtn = dev->my_tx_tasks[i])) {
                        debugFree(dtn, -300066);
                        dev->my_tx_tasks[i]=NULL;
                }

        }
}

STATIC_FUNC
void create_ogm_aggregation(void)
{

        dbgf_all( DBGT_INFO, " ");

        uint32_t n = 0;

        uint32_t target_aggregations = MIN(MAX_OGMS_PER_AGGREG,
                ((ogm_aggreg_pending < ((DEF_OGMS_PER_AGGREG / 3)*4)) ? ogm_aggreg_pending : DEF_OGMS_PER_AGGREG));

        struct msg_ogm_adv* ogm = debugMalloc(target_aggregations * sizeof (struct msg_ogm_adv), -300177);

        static IID_T curr_iid = IID_MIN_USED;

        if (curr_iid >= my_iid_repos.max_free)
                curr_iid = IID_MIN_USED;

        IID_T start_iid = curr_iid;

        dbgf_all( DBGT_INFO, "pending %d target %d start %d",
                ogm_aggreg_pending, target_aggregations, start_iid);

        do {
                IID_NODE_T *dhn = my_iid_repos.arr.node[curr_iid];
                struct orig_node *on;
                int warn = 0;

                while (dhn && (on = dhn->on) &&
                        GREAT_SQN(on->ogm_sqn_to_be_send & on->path_metric_algo.sqn_mask, on->ogm_sqn_aggregated)) {

                        if (GREAT_SQN(on->ogm_sqn_to_be_send & on->path_metric_algo.sqn_mask,
                                on->ogm_sqn_aggregated + on->path_metric_algo.sqn_steps))
                                warn++;

                        if ( warn ) {
                                dbgf(DBGL_CHANGES, DBGT_WARN, "%s delayed %d < %d",
                                        on->id.name, on->ogm_sqn_aggregated, on->ogm_sqn_to_be_send);
                        } else {
                                dbgf_all(DBGT_INFO, "%s in-time %d < %d",
                                        on->id.name, on->ogm_sqn_aggregated, on->ogm_sqn_to_be_send);
                        }


                        on->ogm_sqn_aggregated = on->ogm_sqn_to_be_send & on->path_metric_algo.sqn_mask;

                        ogm[n].orig_sqn = htons(on->ogm_sqn_to_be_send);
                        ogm[n].transmitterIID4x = htons(dhn->myIID4orig);

                        if ((++n) == target_aggregations)
                                goto create_ogm_aggregation_done;
                }

                if ((++curr_iid) >= my_iid_repos.max_free)
                        curr_iid = IID_MIN_USED;

        } while (curr_iid != start_iid);

create_ogm_aggregation_done:

        if (curr_iid == start_iid)
                ogm_aggreg_pending = 0;
        else
                ogm_aggreg_pending -= n;

        if (ogm_aggreg_pending) {
                dbgf(DBGL_SYS, DBGT_WARN, "%d ogms left for immediate next aggregation", ogm_aggreg_pending);
        }

        if (!n) {
                debugFree( ogm, -300219);
                return;
        }

        struct ogm_aggreg_node *oan = debugMalloc(sizeof (struct ogm_aggreg_node), -300179);
        oan->aggregated_ogms = n;
        oan->ogm_advs = ogm;
        oan->tx_attempts = 0;
        oan->tx_timestamp = (bmx_time - DEF_OGM_RESEND_INTERVAL);
        oan->sqn = ++ogm_aggreg_sqn_max;

        dbgf_all( DBGT_INFO, "aggregation_sqn %d aggregated_ogms %d", oan->sqn, n);

        list_add_tail(&ogm_aggreg_list, &oan->list);

        struct avl_node *an = NULL;
        struct neigh_node *nn;

        while ((nn = avl_iterate_item(&neigh_tree, &an))) {

                bit_set(nn->ogm_aggregations_acked, OGM_AGGREG_SQN_CACHE_RANGE, ogm_aggreg_sqn_max, 0);

        }

        return;
}

STATIC_FUNC
struct link_dev_node **get_best_lndevs_by_criteria(struct ogm_aggreg_node *oan_criteria, struct dhash_node *dhn_criteria)
{

        static struct link_dev_node **lndev_arr = NULL;
        static uint16_t lndev_arr_items = 0;
        struct avl_node *an;
        struct neigh_node *nn;
        struct dev_node *dev;
        uint16_t d = 0;

        if (lndev_arr_items < dev_ip4_tree.items + 1) {

                if (lndev_arr)
                        debugFree(lndev_arr, -300180);

                lndev_arr_items = dev_ip4_tree.items + 1;
                lndev_arr = debugMalloc((lndev_arr_items * sizeof (struct link_dev_node*)), -300182);
        }

        if ( oan_criteria || dhn_criteria ) {

                if (oan_criteria) {
                        dbgf_all(DBGT_INFO, "aggreg_sqn %d ", oan_criteria->sqn);
                } else if (dhn_criteria) {
                        dbgf_all(DBGT_INFO, "NOT %s ", dhn_criteria->on->id.name);
                }

                for (an = NULL; (dev = avl_iterate_item(&dev_ip4_tree, &an));)
                        dev->misc_flag = NO;


                for (an = NULL; (nn = avl_iterate_item(&neigh_tree, &an));) {

                        if (oan_criteria &&
                                (bit_get(nn->ogm_aggregations_acked, OGM_AGGREG_SQN_CACHE_RANGE, oan_criteria->sqn) ||
                                nn->best_rtq->mr[SQR_RTQ].val <= MIN_OGM_ACK_RTQ) )
                                continue;

                        if (dhn_criteria && dhn_criteria->neigh == nn)
                                continue;

                        assertion(-500445, (nn->best_rtq));
                        assertion(-500446, (nn->best_rtq->key.dev));
                        assertion(-500447, (nn->best_rtq->key.dev->active));

                        dbgf_all( DBGT_INFO, "  via %s to %s (redundant %d)",
                                nn->best_rtq->key.dev->name, nn->best_rtq->link->llip4_str,
                                nn->best_rtq->key.dev->misc_flag);

                        if (nn->best_rtq->key.dev->misc_flag == NO) {

                                lndev_arr[d++] = nn->best_rtq;

                                nn->best_rtq->key.dev->misc_flag = YES;
                        }

                        assertion(-500444, (d <= dev_ip4_tree.items));

                }
        }

        lndev_arr[d] = NULL;

        return lndev_arr;
}

STATIC_FUNC
void schedule_and_purge_ogm_aggregations(struct dev_node *dev)
{
        static uint32_t timestamp = 0;

        if (dev) {

                dbgf_all( DBGT_INFO, "%s max %d   active aggregations %d   pending ogms %d  expiery in %d ms",
                        dev->name, ogm_aggreg_sqn_max, ogm_aggreg_list.items, ogm_aggreg_pending,
                        (DEF_OGM_AGGREG_INTERVAL - ((uint32_t) (bmx_time - timestamp))));

                while (ogm_aggreg_pending && ((((uint32_t) bmx_time - timestamp)) >= DEF_OGM_AGGREG_INTERVAL)) {

                        struct ogm_aggreg_node *oan = list_get_first(&ogm_aggreg_list);

                        if (oan && ((SQN_T) ((ogm_aggreg_sqn_max + 1) - oan->sqn)) >= OGM_AGGREG_SQN_CACHE_RANGE) {

                                dbgf(DBGL_SYS, DBGT_WARN,
                                        "ogm_aggreg_list full min %d max %d items %d unaggregated %d",
                                        oan->sqn, ogm_aggreg_sqn_max, ogm_aggreg_list.items, ogm_aggreg_pending);

                                debugFree(oan->ogm_advs, -300185);
                                debugFree(oan, -300186);
                                list_del_next(&ogm_aggreg_list, ((struct list_node*) & ogm_aggreg_list));
                        }

                        create_ogm_aggregation();

                        if (!ogm_aggreg_pending)
                                timestamp = bmx_time;
                }
        }

#ifndef NO_PARANOIA
        if (!ogm_aggreg_pending) {
                IID_T i;
                struct dhash_node *dhn;
                for (i = IID_MIN_USED; i < my_iid_repos.max_free && (dhn = my_iid_repos.arr.node[i]); i++) {
                        struct orig_node * on = dhn->on;
                        assertion(-500473,
                                (!(on && GREAT_SQN(on->ogm_sqn_to_be_send & on->path_metric_algo.sqn_mask, on->ogm_sqn_aggregated))));
                }
        }
#endif

        struct list_node *lpos, *tpos, *lprev = (struct list_node*) & ogm_aggreg_list;

        list_for_each_safe(lpos, tpos, &ogm_aggreg_list)
        {
                struct ogm_aggreg_node *oan = list_entry(lpos, struct ogm_aggreg_node, list);

                if (dev == NULL/*purge_all*/ ||
                        ((((uint32_t) (bmx_time - oan->tx_timestamp)) > DEF_OGM_RESEND_INTERVAL) &&
                        oan->tx_attempts > ogm_resend_attempts)) {

                        list_del_next(&ogm_aggreg_list, lprev);
                        debugFree(oan->ogm_advs, -300183);
                        debugFree(oan, -300184);

                        continue;

                } else if ((((uint32_t) (bmx_time - oan->tx_timestamp)) >= DEF_OGM_RESEND_INTERVAL) &&
                        oan->tx_attempts <= ogm_resend_attempts) {

                        struct link_dev_node **lndev_arr = get_best_lndevs_by_criteria(oan, NULL);
                        int d;

                        for (d = 0; (lndev_arr[d]); d++) {
                                schedule_tx_task((lndev_arr[d])->key.dev, NULL, FRAME_TYPE_OGM0_ADVS,
                                        (sizeof (struct hdr_ogm_adv) + (oan->aggregated_ogms * sizeof (struct msg_ogm_adv))),
                                        oan->sqn, 0, 0);
                        }

                        if (!lndev_arr[0])
                                oan->tx_attempts = ogm_resend_attempts;

                        oan->tx_timestamp = bmx_time;
                        oan->tx_attempts++;
                }

                lprev = lpos;
        }
}


STATIC_FUNC
int tx_msg_hello40_reply(struct tx_task_node *ttn, uint8_t *flags, uint8_t *tx_buff, uint16_t buff_size)
{
        struct msg_hello_reply *hey0_rep = (struct msg_hello_reply *) (tx_buff);

        hey0_rep->receiver_ip4 = ttn->dst_ip4;
        hey0_rep->hello_dev_sqn = htons(ttn->sqn);

        dbgf_all( DBGT_INFO, "dev %s %s to %s SQN %d",//  dest_sid: %d",
                ttn->dev->name, ttn->dev->ip4_str, ipStr(ttn->dst_ip4), ttn->sqn/*, dtn->my_id_for_neigh*/);

        return sizeof (struct msg_hello_reply);
}



STATIC_FUNC
int tx_msg_helloX0_adv(struct tx_task_node *ttn, uint8_t *flags, uint8_t *tx_buff, uint16_t buff_size)
{

        struct msg_hello_adv *hey0_adv = (struct msg_hello_adv *) (tx_buff);

        hey0_adv->hello_dev_sqn = htons(++(ttn->dev->ogm_sqn));

        struct avl_node *it;
        struct link_dev_node *lndev;

        for (it = NULL; (lndev = avl_iterate_item(&link_dev_tree, &it));) {
                // we dont want to clean the sqr of other devs
                // update_link_node(ln, ttn->dev, ttn->dev->ogm_sqn, ttn->dev->ogm_sqn, SQR_RTQ, 0);
                if (lndev->key.dev != ttn->dev)
                        continue;

//              update_lounged_metric(0, local_rtq_lounge, ttn->dev->ogm_sqn, ttn->dev->ogm_sqn, &lndev->sqr[SQR_RTQ], local_lws);

                update_metric(&lndev->mr[SQR_RTQ], &link_metric_algo[SQR_RTQ], ttn->dev->ogm_sqn, ttn->dev->ogm_sqn, 0);
        }

        dbgf_all( DBGT_INFO, "%s %s SQN %d", ttn->dev->name, ttn->dev->ip4_str, ttn->dev->ogm_sqn);

        return sizeof (struct msg_hello_adv);
}

STATIC_FUNC
int tx_msg_dhash0_or_description0_request(struct tx_task_node *ttn, uint8_t *flags, uint8_t *tx_buff, uint16_t buff_size)
{
        assertion( -500366 , (sizeof ( struct msg_description_request) == sizeof( struct msg_dhash_request)));

        struct msg_dhash_request *req = (struct msg_dhash_request *) (tx_buff);

        req->receiver_ip4 = ttn->dst_ip4;
        req->receiverIID4x = htons(ttn->neighIID4x);

        dbgf_all( DBGT_INFO, "%s oif %s to %s requesting orig_did %d",
                frame_handler[ttn->frame_type].name, ttn->dev->name, ipStr(ttn->dst_ip4), ttn->neighIID4x);

        return sizeof ( struct msg_description_request);
}


STATIC_FUNC
int tx_msg_description0_adv(struct tx_task_node *ttn, uint8_t *flags, uint8_t *tx_buff, uint16_t buff_size)
{
        struct dhash_node *dhn = NULL;
        struct msg_description_adv *desc0_adv = (struct msg_description_adv *) tx_buff;
        struct description *desc0;

        dbgf_all(DBGT_INFO, "ttn->myIID4x %d", ttn->myIID4x);

        if (ttn->myIID4x == IID_RSVD_4YOU) {

                desc0_adv->transmitterIID4x = htons(myIID4me);
                desc0 = my_orig_node.desc0;
                *flags |= FRAME_FLAG_firstIsSender;

        } else if ((dhn = iid_get_node_by_myIID4x(ttn->myIID4x)) && dhn->on) {

                assertion(-500437, (dhn->on && dhn->on->desc0));

                desc0_adv->transmitterIID4x = htons(ttn->myIID4x);
                desc0 = dhn->on->desc0;

        } else {

                dbgf(DBGL_SYS, DBGT_WARN, "unknown myIID4x %d !", ttn->myIID4x);
                return FAILURE;
        }

        uint16_t tlvs_len = ntohs(desc0->dsc_tlvs_len);

        if (sizeof (struct msg_description_adv) + tlvs_len > buff_size)
                return (buff_size + 1);

        memcpy((char*) & desc0_adv->desc, (char*) desc0, sizeof (struct description) + tlvs_len);

        return sizeof (struct msg_description_adv) + tlvs_len;
}




STATIC_FUNC
int tx_msg_dhash0_adv(struct tx_task_node *ttn, uint8_t *flags, uint8_t *tx_buff, uint16_t buff_size)
{
        struct msg_dhash_adv *dhash0_adv = (struct msg_dhash_adv *) tx_buff;
        struct dhash_node *dhn;

        if (ttn->myIID4x == IID_RSVD_4YOU) {

                dhash0_adv->transmitterIID4x = htons(myIID4me);
                dhn = my_orig_node.dhn;
                *flags |= FRAME_FLAG_firstIsSender;

        } else if ((dhn = iid_get_node_by_myIID4x(ttn->myIID4x)) && dhn->on) {

                assertion(-500259, (dhn->on && dhn->on->desc0));

                dhash0_adv->transmitterIID4x = htons(ttn->myIID4x);

        } else {

                dbgf(DBGL_SYS, DBGT_WARN, "unknown myIID4x %d !", ttn->myIID4x);
                return FAILURE;
        }

        memcpy((char*) & dhash0_adv->dhash, (char*) & dhn->dhash, sizeof ( struct description_hash));

        return sizeof (struct msg_dhash_adv);
}




STATIC_FUNC
int tx_frame_ogm0_advs(struct tx_task_node *ttn, uint8_t *flags, uint8_t *tx_buff, uint16_t buff_size)
{
        struct list_node *list_pos;

        assertion(-500428, (ttn->frame_data_length_target <= buff_size));

        dbgf_all( DBGT_INFO, " aggregation_sqn %d", ttn->sqn );

        list_for_each( list_pos, &ogm_aggreg_list )
        {
                struct ogm_aggreg_node *oan = list_entry(list_pos, struct ogm_aggreg_node, list);

                if ( oan->sqn == ttn->sqn ) {

                        ((struct hdr_ogm_adv*) tx_buff)->aggregation_sqn = htons(ttn->sqn);

                        memcpy(tx_buff + sizeof (struct hdr_ogm_adv),
                                oan->ogm_advs, oan->aggregated_ogms * sizeof (struct msg_ogm_adv));

                        assertion(-500429, (ttn->frame_data_length_target ==
                                (sizeof (struct hdr_ogm_adv) + oan->aggregated_ogms * sizeof (struct msg_ogm_adv))));

                        return ttn->frame_data_length_target;

                }
        }

        return FAILURE;
}


STATIC_FUNC
int tx_msg_ogm_ack(struct tx_task_node *ttn, uint8_t *flags, uint8_t *tx_buff, uint16_t buff_size)
{
        struct msg_ogm_ack *ack = (struct msg_ogm_ack *) tx_buff;

        ack->receiver_ip4 = ttn->dst_ip4;
        ack->aggregation_sqn = htons(ttn->sqn);

        dbgf_all( DBGT_INFO, " aggreg_sqn %d to %s", ttn->sqn, ipStr(ttn->dst_ip4));

        return sizeof (struct msg_ogm_ack);
}


STATIC_FUNC
int rx_frame_ogm0_advs(struct packet_buff *pb, struct frame_header *frame)
{
        struct hdr_ogm_adv *hdr = (struct hdr_ogm_adv *) frame->data;
        struct msg_ogm_adv *ogm = hdr->msg;
        struct neigh_node *nn = pb->ln->neigh;
        
        SQN_T aggregation_sqn = ntohs(hdr->aggregation_sqn);

        uint16_t msgs = (frame->length - (sizeof (struct frame_header) + sizeof (struct hdr_ogm_adv))) /
                sizeof (struct msg_ogm_adv);

        dbgf_all( DBGT_INFO, " ");

        if (!nn) {
                dbgf_all( DBGT_INFO, "via unknown neigh %s", pb->neigh_str );
                schedule_tx_task(pb->iif, pb->lndev, FRAME_TYPE_DHS0_REQS, 0, 0, 0, IID_RSVD_4YOU);
                return frame->length;
        }

        schedule_tx_task(nn->best_rtq->key.dev, nn->best_rtq, FRAME_TYPE_OGM0_ACKS, 0, aggregation_sqn, 0, 0);

        if ((SQN_T) (nn->ogm_aggregation_rcvd_max - aggregation_sqn) < OGM_AGGREG_SQN_CACHE_RANGE) {

                if (bit_get(nn->ogm_aggregations_rcvd, OGM_AGGREG_SQN_CACHE_RANGE, aggregation_sqn)) {

                        dbgf_all( DBGT_INFO, "already known ogm_aggregation_sqn %d from neigh %s",
                                aggregation_sqn, nn->dhn->on->id.name);

                        return frame->length;
                }

                if (((uint16_t) (nn->ogm_aggregation_rcvd_max - aggregation_sqn)) > OGM_AGGREG_SQN_CACHE_WARN) {

                        dbgf(DBGL_CHANGES, DBGT_WARN, "neigh %s with unknown %s aggregation_sqn %d  max %d  ogms %d",
                                pb->neigh_str, "OLD", aggregation_sqn, nn->ogm_aggregation_rcvd_max, msgs);
                }

                bit_set(nn->ogm_aggregations_rcvd, OGM_AGGREG_SQN_CACHE_RANGE, aggregation_sqn, 1);

        } else {

                if (((uint16_t) (aggregation_sqn - nn->ogm_aggregation_rcvd_max)) > OGM_AGGREG_SQN_CACHE_WARN) {

                        dbgf( DBGL_SYS, DBGT_WARN, "neigh %s with unknown %s aggregation_sqn %d  max %d  ogms %d",
                                pb->neigh_str, "LOST", aggregation_sqn, nn->ogm_aggregation_rcvd_max, msgs );
                }

                bit_clear(nn->ogm_aggregations_rcvd, OGM_AGGREG_SQN_CACHE_RANGE, nn->ogm_aggregation_rcvd_max + 1, aggregation_sqn);

                bit_set(nn->ogm_aggregations_rcvd, OGM_AGGREG_SQN_CACHE_RANGE, aggregation_sqn, 1);
                nn->ogm_aggregation_rcvd_max = aggregation_sqn;

        }

        dbgf_all(DBGT_INFO, "neigh %s with unknown %s aggregation_sqn %d  max %d  ogms %d",
                pb->neigh_str, "NEW", aggregation_sqn, nn->ogm_aggregation_rcvd_max, msgs);

        uint16_t m;
        for (m = 0; m < msgs; m++) {

                IID_T neighIID4x = ntohs(ogm[m].transmitterIID4x);
                SQN_T orig_sqn = ntohs(ogm[m].orig_sqn);

                IID_NODE_T *dhn = iid_get_node_by_neighIID4x(nn, neighIID4x );
                struct orig_node *on = NULL;

                if ( dhn == my_orig_node.dhn )
                        continue;


                if (dhn && (on = dhn->on) && ((SQN_T) (orig_sqn - on->ogm_sqn_min)) < on->ogm_sqn_range) {

                        dbgf_all(DBGT_INFO, "    new orig_sqn %d / %d from %s neighIID4x %d via %s ",
                                orig_sqn, on->ogm_sqn_to_be_send, on->id.name, neighIID4x, pb->neigh_str);

                        update_orig_metrics(pb, on, orig_sqn);


                } else {
                        dbgf((dhn && on) ? DBGL_SYS : DBGL_CHANGES, DBGT_WARN,
                                "    %s orig_sqn %d or neighIID4x %d via %s orig %s sqn_min %d sqn_range %d",
                                !dhn ? "UNKNOWN" : on ? "EXCEEDED OGM_SQN RANGE" : "INVALIDATED",
                                orig_sqn, neighIID4x, pb->neigh_str, on ? on->id.name:"---",
                                on ? on->ogm_sqn_min : 0, on ? on->ogm_sqn_range : 0);

                        if (dhn && dhn->on)
                                invalidate_dhash_node(dhn);

                        schedule_tx_task(nn->best_rtq->key.dev, nn->best_rtq, FRAME_TYPE_DHS0_REQS, 0, 0, 0, neighIID4x);
                }
        }

        return frame->length;
}

STATIC_FUNC
int rx_frame_ogm40_acks(struct packet_buff *pb, struct frame_header *frame)
{
        struct msg_ogm_ack *ack = (struct msg_ogm_ack *) frame->data;
        struct neigh_node *nn = pb->ln->neigh;

        uint16_t msgs = (frame->length - (sizeof (struct frame_header))) / sizeof (struct msg_ogm_ack);

        if (!nn) {
                dbgf(DBGL_CHANGES, DBGT_WARN, "%s neigh %s", "unknown", pb->neigh_str);
                schedule_tx_task(pb->iif, pb->lndev, FRAME_TYPE_DHS0_REQS, 0, 0, 0, IID_RSVD_4YOU);
                return frame->length;
        }

        uint16_t m;
        for (m = 0; m < msgs; m++) {

                if ( ack[m].receiver_ip4 != pb->iif->ip4_addr )
                        continue;

                SQN_T aggregation_sqn = ntohs(ack[m].aggregation_sqn);

                if (((uint32_t) (ogm_aggreg_sqn_max - aggregation_sqn) < OGM_AGGREG_SQN_CACHE_RANGE)) {

                        bit_set(pb->ln->neigh->ogm_aggregations_acked, OGM_AGGREG_SQN_CACHE_RANGE, aggregation_sqn, 1);

                        dbgf_all(DBGT_INFO, "neigh %s  sqn %d <= sqn_max %d",
                                pb->neigh_str, aggregation_sqn, ogm_aggreg_sqn_max);


                } else {

                        dbgf(DBGL_SYS, DBGT_ERR, "neigh %s  sqn %d <= sqn_max %d",
                                pb->neigh_str, aggregation_sqn, ogm_aggreg_sqn_max);

                }
        }
        return frame->length;
}


STATIC_FUNC
struct dhash_node *
process_dhash_description_neighIID4x
(struct packet_buff *pb, struct description_hash *dhash, struct description *dsc, IID_T neighIID4x, IDM_T is_sender)
{
        struct dhash_node *orig_dhn = NULL;
        struct link_node *ln = pb->ln;
        IDM_T invalid = NO;
        struct description *cache = NULL;

        if (avl_find(&dhash_invalid_tree, dhash)) {

                invalid = YES;

        } else if ((orig_dhn = avl_find_item(&dhash_tree, dhash))) {

                if (ln->neigh) {

                        // this was just for testing eh???  assertion(-500375, (ln->neigh->dhn == orig_dhn));

                        if (orig_dhn == my_orig_node.dhn) {

                                dbgf_all( DBGT_INFO,
                                        "msg refers myself via %s neighIID4neigh %d neighIID4me %d",
                                        pb->neigh_str, ln->neigh->neighIID4neigh, neighIID4x);

                                if (is_sender)
                                        return FAILURE_POINTER;


                        } else if (orig_dhn == ln->neigh->dhn) {

                                if (!is_sender) {

                                        dbgf(DBGL_SYS, DBGT_ERR, "%s via %s IS NOT sender (%d != %d)",
                                                orig_dhn->on->id.name, pb->neigh_str,
                                                ln->neigh->neighIID4neigh, neighIID4x);

                                        return FAILURE_POINTER;

                                } else if((ln->neigh->neighIID4neigh != neighIID4x)) {

                                        dbgf(DBGL_CHANGES, DBGT_WARN, "%s via %s first contact NOT VIA SENDER ??? %d != %d",
                                                orig_dhn->on->id.name, pb->neigh_str,
                                                ln->neigh->neighIID4neigh, neighIID4x);

                                }
                        }

                        if (is_sender)
                                update_neigh_node(ln, orig_dhn, neighIID4x);

                        else if (update_neighIID4x_repository(ln->neigh, neighIID4x, orig_dhn) == FAILURE)
                                return FAILURE_POINTER;


                } else {

                        if (is_sender) {
                                update_neigh_node(ln, orig_dhn, neighIID4x);
                        } else {
                                //update_neigh_node(ln, dhn, IID_RSVD_UNUSED);
                                //update_neigh_iid_repos(ln->neigh, neighIID4x, dhn);
                        }
                }

        } else {

                // its just the easiest to cache and remove because cache description is doing all the checks for us
                if (dsc)
                        cache_description(dsc, dhash);

                if (is_sender && (cache = rem_cached_description(dhash))) {

                        if ((orig_dhn = process_description(pb, cache, dhash))) {

                                update_neigh_node(ln, orig_dhn, neighIID4x);
                        }

                } else if (ln->neigh && (cache = rem_cached_description(dhash))) {

                        orig_dhn = process_description(pb, cache, dhash);

                        if (orig_dhn && update_neighIID4x_repository(ln->neigh, neighIID4x, orig_dhn) == FAILURE)
                                return FAILURE_POINTER;

                }
        }


        dbgf_all( DBGT_INFO, "via dev: %s NB %s:dhash %8X.. %s neighIID4x %d  is_sender %d %s",
                pb->iif->name, pb->neigh_str, dhash->h.u32[0],
                (dsc ? "DESCRIPTION" : (cache ? "CACHED_DESCRIPTION" : (orig_dhn?"KNOWN":"UNDESCRIBED"))),
                neighIID4x, is_sender,
                invalid ? "INVALIDATED" : (orig_dhn && orig_dhn->on ? orig_dhn->on->id.name : "---"));


        return orig_dhn;
}


STATIC_FUNC
int rx_frame_dhash0_advs(struct packet_buff *pb, struct frame_header *frame)
{

        assertion(-500373, (pb->ln && pb->lndev && pb->lndev->mr[SQR_RTQ].val >= MIN_NBDISC_RTQ));

        int m, n = (frame->length - sizeof (struct frame_header)) / sizeof ( struct msg_dhash_adv);

        for (m = 0; m < n; m++) {

                struct msg_dhash_adv *msg = &(((struct msg_dhash_adv*) (frame->data))[m]);
                IDM_T is_sender = (m == 0 && (frame->flags & FRAME_FLAG_firstIsSender));
                IID_T neighIID4x = ntohs(msg->transmitterIID4x);
                struct dhash_node *dhn;

                if ( neighIID4x <= IID_RSVD_MAX )
                        return FAILURE;

                dhn = process_dhash_description_neighIID4x(pb, &msg->dhash, NULL, neighIID4x, is_sender);

                if (dhn == FAILURE_POINTER) {

                        return FAILURE;

                } else if (!dhn) {

                        schedule_tx_task(pb->iif, pb->lndev, FRAME_TYPE_DSC0_REQS, 0, 0, 0, neighIID4x);

                }/* else if (dhn && is_sender && !pb->ln->neigh) {

                        schedule_tx_task(pb->iif, pb->lndev, FRAME_TYPE_DHS0_REQS, 0, 0, 0, IID_RSVD_4YOU);
                }*/

                paranoia(-500488, (dhn && is_sender && !pb->ln->neigh));


        }
        return frame->length;
}


STATIC_FUNC
int rx_frame_description0_advs(struct packet_buff *pb, struct frame_header *frame)
{

        uint16_t pos = sizeof ( struct frame_header);

        struct description_hash dhash0;

        while (pos + sizeof ( struct msg_description_adv) <= frame->length) {

                IDM_T is_sender = (pos == sizeof ( struct frame_header) && (frame->flags & FRAME_FLAG_firstIsSender));
                struct msg_description_adv *adv = ((struct msg_description_adv*) (((char*)frame)+pos));
                struct description *desc0 = &adv->desc;
                uint16_t tlvs_len = ntohs(desc0->dsc_tlvs_len);
                IID_T neighIID4x = ntohs(adv->transmitterIID4x);
                struct dhash_node *dhn;
                
                if ( neighIID4x <= IID_RSVD_MAX )
                        return FAILURE;

                if (tlvs_len > MAX_DESC0_TLV_SIZE ||
                        pos + sizeof ( struct msg_description_adv) + tlvs_len > frame->length) {

                        dbgf( DBGL_SYS, DBGT_ERR, "illegal pos %d + %lu tlvs_len %d > frm_size %d",
                                pos, sizeof ( struct msg_description_adv), tlvs_len, frame->length );

                        return FAILURE;
                }

                ShaUpdate(&bmx_sha, (byte*) desc0, (sizeof (struct description) + tlvs_len));
                ShaFinal(&bmx_sha, (byte*)&dhash0);

                dhn = process_dhash_description_neighIID4x(pb, &dhash0, desc0, neighIID4x, is_sender);

                dbgf_all( DBGT_INFO, "rcvd %s desc0: %jX via %s NB %s",
                        dhn ? "accepted" : "denied", desc0->id.rand.u64[0], pb->iif->name, pb->neigh_str);


                if (dhn == FAILURE_POINTER) {

                        return FAILURE;

                } else if (dhn && dhn->on->updated_timestamp == bmx_time && pb->ln->neigh && DEF_UNSOLICITED_DESCRIPTIONS) {

                        struct link_dev_node **lndev_arr = get_best_lndevs_by_criteria(NULL, pb->ln->neigh->dhn);
                        int d;

                        uint16_t desc_len = sizeof ( struct msg_description_adv) + ntohs(dhn->on->desc0->dsc_tlvs_len);

                        for (d = 0; (lndev_arr[d]); d++)
                                schedule_tx_task(lndev_arr[d]->key.dev, lndev_arr[d], FRAME_TYPE_DSC0_ADVS, desc_len, 0, dhn->myIID4orig, 0);


                }


                paranoia(-500379, (dhn && is_sender && !pb->ln->neigh));

                pos += sizeof ( struct msg_description_adv) + tlvs_len;
        }

        if (frame->length != pos)
                return FAILURE;


        return frame->length;
}

STATIC_FUNC
int rx_frame_dhash0_or_description0_requests(struct packet_buff *pb, struct frame_header *frame)
{
        assertion( -500365 , (sizeof( struct msg_description_request ) == sizeof( struct msg_dhash_request)));

        int m, n = (frame->length - sizeof (struct frame_header)) / sizeof ( struct msg_description_request);

        uint8_t frame_type = frame->type;


        for (m = 0; m < n; m++) {

                struct msg_description_request *req = &(((struct msg_description_request*) (frame->data))[m]);
                IID_T myIID4x = ntohs(req->receiverIID4x);
                uint16_t desc0_len = 0;

                dbgf_all( DBGT_INFO, "%s dest_llip4 %s myIID4x %d",
                        frame_handler[frame_type].name, ipStr(req->receiver_ip4), myIID4x);

                if ( req->receiver_ip4 != pb->iif->ip4_addr ) // if I am not asked
                        continue;


                if (myIID4x == IID_RSVD_4YOU || myIID4x == myIID4me) {

                        myIID4x = IID_RSVD_4YOU;

                        desc0_len = sizeof ( struct msg_description_adv) + my_desc0_tlv_len;

                } else { // if I am asked for somebody else description

                        struct dhash_node *dhn = iid_get_node_by_myIID4x(myIID4x);
                        
                        assertion(-500270, (!(dhn && dhn->on && !dhn->on->desc0)));

                        if (myIID4x <= IID_RSVD_MAX || !dhn || !dhn->on ||
                                ((uint32_t) (bmx_time - dhn->referred_timestamp)) > DEF_DESC0_REFERRED_TO) {

                                dbgf(DBGL_SYS, DBGT_WARN,
                                        "%s from %s via %s myIID4x %d requesting %s",
                                        frame_handler[frame_type].name, pb->ln->llip4_str, pb->iif->name, myIID4x,
                                        !dhn ? "UNKNOWN" : (dhn->on ? "OUTDATED" : "INVALID"));

                                continue;
                        }

                        assertion(-500251, (dhn && dhn->on && dhn->myIID4orig == myIID4x));
                        desc0_len = sizeof ( struct msg_description_adv) + ntohs(dhn->on->desc0->dsc_tlvs_len);
                }


                if ( frame_type == FRAME_TYPE_DSC0_REQS) {

                        schedule_tx_task(pb->iif, pb->lndev, FRAME_TYPE_DSC0_ADVS, desc0_len, 0, myIID4x, 0);

                } else {

                        schedule_tx_task(pb->iif, pb->lndev, FRAME_TYPE_DHS0_ADVS, 0, 0, myIID4x, 0);
                }
        }

        return frame->length;
}

STATIC_FUNC
int rx_frame_hello40_replies(struct packet_buff *pb, struct frame_header *frame)
{

        int found = 0, m, n = (frame->length - sizeof (struct frame_header)) / sizeof ( struct msg_hello_reply);

        for (m = 0; m < n; m++) {

                struct msg_hello_reply *msg = &(((struct msg_hello_reply*) (frame->data))[m]);

                SQN_T sqn = ntohs(msg->hello_dev_sqn);

                dbgf_all( DBGT_INFO, "via NB %s dev %s %s to %s SQN %d",
                        pb->neigh_str, pb->iif->name, pb->iif->ip4_str, ipStr(msg->receiver_ip4), sqn);

                if ( msg->receiver_ip4 != pb->iif->ip4_addr )
                        continue;


                if ((SQN_T) (pb->iif->ogm_sqn - sqn) > (SQN_T) local_rtq_lounge) {

                        dbgf(DBGL_SYS, DBGT_ERR, "DAD-Alert invalid Link-Local SQN %d!=%d from %s via %s",
                                sqn, pb->iif->ogm_sqn, pb->neigh_str, pb->iif->name);

                        return FAILURE;
                }

                found++;

                if( !pb->ln->neigh)
                        schedule_tx_task(pb->iif, pb->lndev, FRAME_TYPE_DHS0_REQS, 0, 0, 0, IID_RSVD_4YOU);

                update_link_node(pb->ln, pb->iif, sqn, pb->iif->ogm_sqn, SQR_RTQ, PROBE_RANGE);

        }

        if (found > 1) {
                dbgf(DBGL_CHANGES, DBGT_WARN,
                        "rcvd %d %s messages in %d-bytes frame",
                        found, frame_handler[FRAME_TYPE_HI40_REPS].name, frame->length);
        }

        return frame->length;

}



STATIC_FUNC
int rx_frame_helloX0_advs( struct packet_buff *pb, struct frame_header *frame )
{

        struct link_node *ln = pb->ln;

        int m, n = (frame->length - sizeof (struct frame_header)) / sizeof ( struct msg_hello_adv);

        if (frame->length != sizeof ( struct frame_header) + sizeof ( struct msg_hello_adv)) {
                dbgf(DBGL_SYS, DBGT_WARN,
                        "rcvd %d %s messages in %d-bytes frame",
                        n, frame_handler[FRAME_TYPE_HI40_ADVS].name, frame->length);
        }

        for (m = 0; m < n; m++) {

                struct msg_hello_adv *msg = &(((struct msg_hello_adv*) (frame->data))[m]);

                SQN_T sqn = ntohs(msg->hello_dev_sqn);

                dbgf_all( DBGT_INFO, "NB %s via %s  SQN %d ", pb->neigh_str, pb->iif->name, sqn);

                // skip updateing link_node if this SQN is known but not new
                if ((ln->rq_sqn_max || ln->rq_time_max) &&
                        ((SQN_T) (sqn - ln->rq_sqn_max) > SQN_DAD_RANGE) &&
                        ((uint32_t) (bmx_time - ln->rq_time_max) < (uint32_t) dad_to)) {

                        dbgf(DBGL_SYS, DBGT_INFO, "DAD-Alert NB %s via %s SQN %d rq_sqn_max %d",
                                pb->neigh_str, pb->iif->name, sqn, ln->rq_sqn_max);

                        return FAILURE;
                }

                schedule_tx_task(pb->iif, pb->lndev, FRAME_TYPE_HI40_REPS, 0, sqn, 0, 0);

                update_link_node(ln, pb->iif, sqn, sqn, SQR_RQ, PROBE_RANGE);

        }

        return frame->length;
}



int rx_frames(struct packet_buff *pb, uint8_t* fdata, uint16_t fsize)
{

        uint16_t frm_pos = 0;
        int t = 0, pt = 0;

        struct frame_header *fhdr = NULL;
        uint16_t flength = 0;

        while (frm_pos + sizeof ( struct frame_header) < fsize) {

                fhdr = (struct frame_header*) & (fdata[frm_pos]);
                flength = fhdr->length = ntohs(fhdr->length);
                int receptor_result;

                if ((t = fhdr->type) < pt || flength < sizeof ( struct frame_header) || flength + frm_pos > fsize) {

                        goto rx_frames_frm_error;
                }

                struct pkt_frame_handler *fhdl = &frame_handler[t];

                dbgf_all( DBGT_INFO, "type %s  size %d  flags 0x%X",
                        fhdl->name, flength, fhdr->flags);


                if (t > FRAME_TYPE_NOP || !(fhdl->rx_frm_receptor)) {

                        dbgf(DBGL_SYS, DBGT_WARN, "unsupported type %d ! maybe you need an update?", t);

                        if (t > FRAME_TYPE_NOP)
                                goto rx_frames_frm_error;

                } else if (flength - sizeof (struct frame_header) < fhdl->data_header_size + fhdl->min_msg_size) {

                        dbgf(DBGL_SYS, DBGT_WARN,
                                "too small size %d for type %s", flength, fhdl->name);
                        goto rx_frames_frm_error;

                } else if (fhdl->fixed_msg_size &&
                        (flength - (sizeof (struct frame_header) + fhdl->data_header_size)) % fhdl->min_msg_size) {

                        dbgf(DBGL_SYS, DBGT_WARN,
                                "nonmaching size %d for type %s", flength, fhdl->name);
                        goto rx_frames_frm_error;

                } else if (fhdl->min_rtq && (!pb->lndev || pb->lndev->mr[SQR_RTQ].val < fhdl->min_rtq)) {

                        dbg_mute(60, DBGL_CHANGES, DBGT_WARN,
                                "non-sufficient bidirectional link %s - %s (rtq %d), skipping frame type %s",
                                pb->iif->ip4_str, pb->neigh_str,
                                pb->lndev ? pb->lndev->mr[SQR_RTQ].val : 0, fhdl->name);

                } else if (flength != (receptor_result = (*(fhdl->rx_frm_receptor)) (pb, fhdr))) {

                        if (receptor_result == FAILURE)
                                blacklist_neighbor(pb);

                        goto rx_frames_msg_error;

                }

                pt = t;
                frm_pos += flength;
         }

        if ( frm_pos != fsize )
                goto rx_frames_frm_error;

        return SUCCESS;

rx_frames_msg_error:
        dbgf(DBGL_SYS, DBGT_WARN, "rcvd problematic message");

rx_frames_frm_error:
        dbgf(DBGL_SYS, DBGT_WARN,
                "rcvd problematic frame type %s last %s  frm_size %d  pos %d ",
                frame_handler[t].name, frame_handler[pt].name, flength, frm_pos);

        return FAILURE;
}




STATIC_FUNC
int8_t send_udp_packet( unsigned char *upd_data, int32_t udp_len, struct sockaddr_in *dst, int32_t send_sock ) {

	int status;

	dbgf_all( DBGT_INFO, "len %d", udp_len );

	if ( send_sock == 0 )
		return 0;

	/*
	static struct iovec iov;
	iov.iov_base = udp_data;
	iov.iov_len  = udp_data_len;

	static struct msghdr m = { 0, sizeof( struct sockaddr_in ), &iov, 1, NULL, 0, 0 };
	m.msg_name = dst;

	status = sendmsg( send_sock, &m, 0 );
	*/

	status = sendto( send_sock, upd_data, udp_len, 0, (struct sockaddr *)dst, sizeof(struct sockaddr_in) );

	if ( status < 0 ) {

		if ( errno == 1 ) {

			dbg_mute( 60, DBGL_SYS, DBGT_ERR,
			     "can't send udp packet: %s. Does your firewall allow outgoing packets on port %i ?",
			     strerror(errno), ntohs(dst->sin_port));

		} else {

			dbg_mute( 60, DBGL_SYS, DBGT_ERR, "can't send udp packet via fd %d: %s", send_sock, strerror(errno));

		}

		return -1;
	}

	return 0;
}



void tx_packet( void *dev_node )
{
        static unsigned char tx_buff[MAX_UDPD_SIZE+1];
        struct dev_node *dev = dev_node;
        struct packet_header *packet_hdr = (struct packet_header *) tx_buff;
        memset( packet_hdr, 0, sizeof( tx_buff ));
        uint16_t packet_size = sizeof( struct packet_header );
        IDM_T packet_full = NO;

        assertion( -500204, dev );
        assertion( -500205, dev->active );

        //remove_task( tx_packet, dev );
        register_task(aggreg_interval - (1 + rand_num(aggreg_interval / 10)), tx_packet, dev);

        schedule_and_purge_ogm_aggregations(dev);

        uint16_t type = 0; // the currently processed frame_type

        while (type <= FRAME_TYPE_NOP) {

                uint16_t length = sizeof (struct frame_header);
                uint8_t flags = 0;

                int creator_result;
                struct pkt_frame_handler *fhdl = &frame_handler[type];
                struct tx_task_node *ttn;
                IDM_T frame_full = NO;

                assertion(-500351, (!(fhdl->tx_frm_creator && fhdl->tx_msg_creator)));

                if ((ttn = dev->my_tx_tasks[type])) {

                        assertion(-500422, (!fhdl->data_header_size));
                        assertion(-500424, (fhdl->tx_msg_creator));
                        assertion(-500441, (ttn->myIID4x == IID_RSVD_4YOU));

                        dbgf_all( DBGT_INFO, "%s type %d=%s %s",
                                dev->name, type, fhdl->name, "from dev->my_tx_tasks");

                        if (tx_task_obsolete(dev, type, ttn)) {

                                creator_result = FAILURE;

                        } else if (packet_full ||
                                (fhdl->fixed_msg_size &&
                                packet_size + length + ttn->frame_data_length_target > (uint16_t) max_udpd_size)
                                ) {

                                creator_result = max_udpd_size + 1;

                        } else {

                                creator_result = (*(fhdl->tx_msg_creator))
                                        (ttn, &flags, (tx_buff + packet_size + length),
                                        (max_udpd_size - (packet_size + length)));

                        }

                        if (creator_result > (max_udpd_size - (packet_size + length))) {

                                assertion(-500431,
                                        (packet_size > sizeof ( struct packet_header) ||
                                        length > sizeof (struct frame_header)));

                                packet_full = YES;

                        } else if (creator_result) {

                                if (creator_result > 0)
                                        length += creator_result;

                                freed_tx_task_node(ttn, creator_result, NULL);

                        }
                }

                struct list_node *lprev = (struct list_node*) &(dev->tx_tasks_list[type]);
                struct list_node *lpos, *ltmp;

                list_for_each_safe(lpos, ltmp, &(dev->tx_tasks_list[type]))
                {
                        ttn = list_entry(lpos, struct tx_task_node, list);

                        assertion(-500440, (ttn->frame_type == type));

                        dbgf_all( DBGT_INFO, "%s type %d=%s %s",
                                dev->name, type, fhdl->name, "from dev->tx_tasks_list");

                        if (ttn->tx_timestamp == bmx_time) {

                                // just send! send again later;
                                creator_result = 0;

                        } else if (tx_task_obsolete(dev, type, ttn)) {

                                creator_result = FAILURE;

                        } else if (packet_full ||
                                (fhdl->fixed_msg_size &&
                                packet_size + length + ttn->frame_data_length_target > (uint16_t) max_udpd_size)
                                ) {

                                creator_result = max_udpd_size + 1;

                        } else if (fhdl->tx_frm_creator) {

                                creator_result = ((*(fhdl->tx_frm_creator))
                                        (ttn, &flags, (tx_buff + packet_size + length),
                                        (max_udpd_size - (packet_size + length))));

                                frame_full = YES;

                        } else {

                                assertion(-500425, (fhdl->tx_msg_creator));
                                assertion(-500426, (!fhdl->data_header_size)); // to be implemented...

                                creator_result = (*(fhdl->tx_msg_creator))
                                        (ttn, &flags, (tx_buff + packet_size + length),
                                        (max_udpd_size - (packet_size + length)));

                        }

                        if (creator_result > (max_udpd_size - (packet_size + length))) {

                                assertion(-500430,
                                        (packet_size > sizeof ( struct packet_header) ||
                                        length > sizeof (struct frame_header)));

                                packet_full = YES;
                                break;

                        } else if (creator_result) {

                                if (creator_result > 0)
                                        length += creator_result;

                                if (freed_tx_task_node(ttn, creator_result, lprev) == NO)
                                        lprev = lpos;

                                if (frame_full)
                                        break;

                                continue;

                        } else {
                                lprev = lpos;
                        }
                }


                if (length > sizeof (struct frame_header)) {

                        struct frame_header *frame_hdr = (struct frame_header *) (tx_buff + packet_size);
                        packet_size += length;

                        frame_hdr->type = type;
                        frame_hdr->length = htons(length);
                        frame_hdr->flags |= flags;

                        dbgf_all( DBGT_INFO, "send frame type %s  size %d", fhdl->name, length);
                }


                if (packet_full || (type == FRAME_TYPE_NOP && packet_size > sizeof ( struct packet_header))) {

                        assertion(-500208, (packet_size <= max_udpd_size));
                        assertion(-500412, (packet_size >= sizeof ( struct packet_header)));

                        packet_hdr->bmx_version = COMPAT_VERSION;
                        packet_hdr->bmx_capabilities = 0;
                        packet_hdr->pkt_length = htons(packet_size);
                        packet_hdr->pkt_dev_sqn = htons(++(dev->packet_sqn));

                        send_udp_packet(tx_buff, packet_size, &dev->ip4_netwbrc_addr, dev->unicast_sock);

                        dbgf_all( DBGT_INFO, "send packet  size %d  via dev %s", packet_size, dev->name);

                        packet_size = sizeof ( struct packet_header);
                        packet_full = NO;
                }

                if (type == FRAME_TYPE_NOP ||
                        !dev->tx_tasks_list[type].items ||
                        ((struct tx_task_node*) (list_get_last(&(dev->tx_tasks_list[type]))))->tx_timestamp == bmx_time) {

                        CHECK_INTEGRITY();

                        type++;
                }
        }
}



void schedule_my_hello_message( void* dev_node ) {

        struct dev_node * dev = dev_node;

        paranoia( -500206, !dev );
        paranoia( -500207, !dev->active );

	register_task( my_hello_interval, schedule_my_hello_message, dev );

        dbgf_all( DBGT_INFO, "%s", dev->name);

        if (!LIST_EMPTY(&(dev->tx_tasks_list[FRAME_TYPE_HI40_ADVS]))) {
                dbgf( DBGL_SYS, DBGT_ERR, " ");
        }

        schedule_tx_task( dev, NULL, FRAME_TYPE_HI40_ADVS, 0, 0, 0, 0 );
}


void schedule_my_originator_message( void* unused )
{
        my_orig_node.ogm_sqn_to_be_send += my_orig_node.path_metric_algo.sqn_steps;  //ogm_sqn_steps;
        my_orig_node.dhn->referred_timestamp = bmx_time;

        register_task(my_ogm_interval, schedule_my_originator_message, NULL);

        if (((uint32_t) (my_orig_node.ogm_sqn_to_be_send + 1 - my_orig_node.ogm_sqn_min)) < my_orig_node.ogm_sqn_range) {

                ogm_aggreg_pending++;
                dbgf_all(DBGT_INFO, "ogm_sqn %d", my_orig_node.ogm_sqn_to_be_send);

        } else {

                update_my_description_adv();

        }
}




void update_my_description_adv(void)
{
        struct description_hash dhash;
        struct description *dsc = my_orig_node.desc0;

        if ( terminating() )
                return;

        // put obligatory stuff:
        memset(dsc, 0, MAX_PKT_MSG_SIZE);

        memcpy(&dsc->id, &my_orig_node.id, sizeof(struct description_id));
/*
        dsc->id.rand.u32[0] = htonl(my_orig_node.id.rand.u32[0]);
        dsc->id.rand.u32[1] = htonl(my_orig_node.id.rand.u32[1]);
*/


        my_orig_node.ogm_sqn_pq_bits = DEF_OGM0_PQ_BITS;
//        my_orig_node.ogm_sqn_mask = (MAX_SQN << my_orig_node.ogm_sqn_pq_bits);
//        my_orig_node.ogm_sqn_steps = (0x01 << my_orig_node.ogm_sqn_pq_bits);

        // add some randomness to the ogm_sqn_range, that not all nodes invalidate at the same time:
        uint16_t random_range = ((DEF_OGM0_SQN_RANGE - (DEF_OGM0_SQN_RANGE/5)) > MIN_OGM0_SQN_RANGE) ?
                DEF_OGM0_SQN_RANGE - rand_num(DEF_OGM0_SQN_RANGE/5) : DEF_OGM0_SQN_RANGE + rand_num(DEF_OGM0_SQN_RANGE/5);

        my_orig_node.ogm_sqn_range = ((random_range + my_orig_node.path_metric_algo.sqn_steps - 1) & my_orig_node.path_metric_algo.sqn_mask);

        my_orig_node.ogm_sqn_min = ((my_orig_node.ogm_sqn_min + MAX_OGM0_SQN_RANGE + (0x01 << MAX_OGM0_PQ_BITS)) & my_orig_node.path_metric_algo.sqn_mask);

        my_orig_node.ogm_sqn_aggregated = my_orig_node.ogm_sqn_min;
        my_orig_node.ogm_sqn_to_be_send = my_orig_node.ogm_sqn_min + my_orig_node.path_metric_algo.sqn_steps - 1;


        dsc->path_window_size = htons(my_orig_node.path_metric_algo.sqn_window);
        dsc->path_lounge_size = htons(my_orig_node.path_metric_algo.sqn_lounge);


        dsc->ttl_max = my_ttl;
        dsc->path_hystere = my_path_hystere;

        dsc->hop_penalty = my_hop_penalty;
        dsc->late_penalty = my_late_penalty;
        dsc->asym_weight = asym_weight;
        dsc->sym_weight = sym_weight;


        dsc->ogm_sqn_pq_bits = my_orig_node.ogm_sqn_pq_bits;
        dsc->ogm_sqn_min = htons(my_orig_node.ogm_sqn_min);
        dsc->ogm_sqn_range = htons(my_orig_node.ogm_sqn_range);

        dsc->dsc_sqn = htons(++(my_orig_node.desc0_sqn));


        dsc->path_ogi = htons(my_ogm_interval);


        // add all tlv options:
        my_desc0_tlv_len = 0;
        uint8_t tlvt;
        for ( tlvt=0; tlvt < BMX_DSC_TLV_ARRSZ; tlvt++) {

                struct frame_header *tlv = (struct frame_header*) (((char*) dsc) + sizeof (struct description) + my_desc0_tlv_len);

                uint16_t rsvd = my_desc0_tlv_len + sizeof (struct frame_header);

                if (rsvd <= MAX_DESC0_TLV_SIZE && (description0_tlv_handler[tlvt].create_tlv)) {

                        uint16_t msgs_size = (*(description0_tlv_handler[tlvt].create_tlv))
                                (tlv->data, MAX_DESC0_TLV_SIZE - rsvd);

                        if ( msgs_size ) {

                                assertion(-500355, (description0_tlv_handler[tlvt].variable_msg_size ||
                                        msgs_size % description0_tlv_handler[tlvt].min_msg_size == 0));

                                tlv->type = tlvt;
                                tlv->length = htons(sizeof (struct frame_header) + msgs_size);

                                my_desc0_tlv_len += sizeof (struct frame_header) + msgs_size;

                                dbgf_all(DBGT_INFO, "added %s size %d",
                                        description0_tlv_handler[tlvt].name, msgs_size);

                        }

                } else {
                        cleanup_all( -500352 );
                }
        }

        dsc->dsc_tlvs_len = htons(my_desc0_tlv_len);

        dbgf_all(DBGT_INFO, "added tlv total of %d ", my_desc0_tlv_len);

        // calculate hash: like shown in CTaoCrypt Usage Reference:
        ShaUpdate(&bmx_sha, (byte*)dsc, (sizeof (struct description) + my_desc0_tlv_len));
        ShaFinal(&bmx_sha, (byte*) &dhash);

        if ( my_orig_node.dhn ) {
                my_orig_node.dhn->on = NULL;
                invalidate_dhash_node( my_orig_node.dhn );
        }

        my_orig_node.dhn = create_dhash_node(&dhash,  &my_orig_node);

        myIID4me = my_orig_node.dhn->myIID4orig;

        if (DEF_UNSOLICITED_DESCRIPTIONS) {
                uint16_t desc_len = sizeof ( struct msg_description_adv) + my_desc0_tlv_len;
                struct link_dev_node **lndev_arr = get_best_lndevs_by_criteria(NULL, my_orig_node.dhn);
                int d;

                for (d = 0; (lndev_arr[d]); d++)
                        schedule_tx_task(lndev_arr[d]->key.dev, lndev_arr[d], FRAME_TYPE_DSC0_ADVS, desc_len, 0, IID_RSVD_4YOU, 0);
        }

/*
        remove_task(schedule_my_originator_message, NULL);
        register_task(1, schedule_my_originator_message, NULL);
*/


}



static struct opt_type msg_options[]=
{
//       ord parent long_name             shrt Attributes                            *ival              min                 max                default              *func,*syntax,*help

	{ODI, 0,0,                         0,  5,0,0,0,0,0,                          0,                 0,                  0,                 0,                   0,
			0,		"\nMessage options:"}
,
        {ODI, 0, ARG_UDPD_SIZE,            0,  5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &max_udpd_size,   MIN_UDPD_SIZE,      MAX_UDPD_SIZE,     DEF_UDPD_SIZE,       0,
			ARG_VALUE_FORM,	"set preferred udp-data size for send packets"}
,
        {ODI, 0, ARG_AGGREG_INTERVAL,      0,  5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &aggreg_interval,  MIN_AGGREG_INTERVAL,MAX_AGGREG_INTERVAL,DEF_AGGREG_INTERVAL,0,
			ARG_VALUE_FORM,	"set aggregation interval (SHOULD be smaller than the half of your and others OGM interval)"}
,
        {ODI, 0, ARG_OGM_RESEND_ATTEMPTS,  0,  5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &ogm_resend_attempts,MIN_OGM_RESEND_ATTEMPTS,MAX_OGM_RESEND_ATTEMPTS,DEF_OGM_RESEND_ATTEMPTS,0,
			ARG_VALUE_FORM,	"set maximum resend attempts for ogm aggregations"}
,
        {ODI, 0, ARG_HELLO_INTERVAL,       'O',5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_hello_interval,MIN_HELLO_INTERVAL, MAX_HELLO_INTERVAL, DEF_HELLO_INTERVAL, 0,
			ARG_VALUE_FORM,	"set interval in ms with which new originator message (OGM) are send"}
,
        {ODI, 0, ARG_OGM_INTERVAL,         'o',5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_ogm_interval,  MIN_OGM_INTERVAL,   MAX_OGM_INTERVAL,   DEF_OGM_INTERVAL,   opt_update_description,
			ARG_VALUE_FORM,	"set interval in ms with which new originator message (OGM) are send"}

};


void init_msg( void )
{

        paranoia( -500347, ( sizeof(struct description_hash) != BMX_HASH0_LEN));

        ogm_aggreg_sqn_max = rand_num(MAX_SQN);

	register_options_array( msg_options, sizeof( msg_options ) );

        InitSha(&bmx_sha);

        register_task(rand_num(RAND_INIT_DELAY), schedule_my_originator_message, NULL);

}

void cleanup_msg( void )
{
        schedule_and_purge_ogm_aggregations(NULL /*purge_all*/);

        debugFree(get_best_lndevs_by_criteria(NULL, NULL), -300218);
        
        purge_cached_descriptions(YES);

}
