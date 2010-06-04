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


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>



#include "bmx.h"
#include "msg.h"
#include "plugin.h"
#include "hna.h"
#include "route.h"

AVL_TREE(global_uhna_tree, struct uhna4_node, key );
AVL_TREE(local_uhna_tree, struct uhna4_node, key );

/*
struct uhna4_node *get_global_uhna_node(struct uhna4_key* key)
{
        return avl_find_item(&global_uhna_tree, key);
}
*/


void set_uhna4_key(struct uhna4_key *key, uint8_t prefix_len, IP4_T glip4, uint32_t metric)
{
        memset( key, 0, sizeof(struct uhna4_key));
        key->prefix_len = prefix_len;
        key->glip4 = glip4;
        key->metric_be = htonl(metric);

}





int create_description_tlv_ip4(uint8_t *data, uint16_t max_size)
{
        struct avl_node *it = NULL;
        struct dev_node *dev = primary_if;
        int item = 0;
        struct description0_msg_ip4 *glip4 = (struct description0_msg_ip4*) data;

        do {
                if (item == 0 || (dev != primary_if && dev->announce)) {

                        if ((item+1) * sizeof (struct description0_msg_ip4) > max_size) {

                                dbgf(DBGL_SYS, DBGT_ERR, "unable to announce %s %s due to limiting --%s=%d",
                                        dev->name, dev->ip4_str, ARG_UDPD_SIZE, max_size);
                                break;
                        }

                        glip4[item++].ip4 = dev->ip4_addr;
                }

        } while ((dev = avl_iterate_item(&dev_ip4_tree, &it)));

        return item * sizeof (struct description0_msg_ip4);
}

int create_description_tlv_hna4(uint8_t *data, uint16_t max_size)
{
        struct avl_node *it = NULL;
        struct dev_node *dev;
        struct uhna4_node *un;
        int item = 0;
        struct description0_msg_hna4 *uhna4 = (struct description0_msg_hna4*) data;

        while ((un = avl_iterate_item(&local_uhna_tree, &it))) {

                if (!un->key.metric_be && un->key.prefix_len==32 &&
                        (dev = avl_find_item(&dev_ip4_tree, &(un->key.glip4))) && dev->announce)
                        continue;

                if (item * sizeof (struct description0_msg_hna4) > max_size) {

                        dbgf( DBGL_SYS, DBGT_ERR, "unable to announce %s/%d metric %d due to limiting --%s=%d",
                                ipStr(un->key.glip4), un->key.prefix_len, ntohl(un->key.metric_be),
                                ARG_UDPD_SIZE, max_size );
                        continue;
                }

                uhna4[item].ip4 = un->key.glip4;
                uhna4[item].metric = un->key.metric_be;
                uhna4[item].prefix_len = un->key.prefix_len;
                item++;
        }

        return item * sizeof (struct description0_msg_hna4);
}



int process_description_tlv_hna4(struct orig_node *on, struct frame_header *tlv, IDM_T op, struct ctrl_node *cn )
{
        struct description0_msg_ip4 *glip4 = NULL;
        struct description0_msg_hna4 *uhna4 = NULL;

        assertion(-500357, (tlv->type == BMX_DSC_TLV_GLIP4 || tlv->type == BMX_DSC_TLV_UHNA4));

        uint16_t msgs_size = ntohs(tlv->length) - sizeof (struct frame_header);
        uint16_t msg_size, m, msgs;

        if (tlv->type == BMX_DSC_TLV_GLIP4) {
                glip4 = (struct description0_msg_ip4 *) tlv->data;
                msg_size = sizeof (struct description0_msg_ip4);
        } else {
                uhna4 = (struct description0_msg_hna4 *) tlv->data;
                msg_size = sizeof (struct description0_msg_hna4);
        }

        msgs = msgs_size / msg_size;

        for (m = 0; m < msgs; m++) {
                struct uhna4_key key;

                if (glip4) {
                        set_uhna4_key(&key, 32, glip4[m].ip4, 0);
                } else {
                        set_uhna4_key(&key, uhna4[m].prefix_len, uhna4[m].ip4, ntohl(uhna4[m].metric));
                }

                dbgf_all( DBGT_INFO, "%s %s %s/%d metric %d",
                        tlv_op_str[op], glip4 ? "glip4:" : "uhna4:",
                        ipStr(key.glip4), key.prefix_len, ntohl(key.metric_be));

                if (op == TLV_DEL_TEST_ADD) {

                        struct uhna4_node *un = avl_remove(&global_uhna_tree, &key, -300215);
                        assertion(-500358, (un && un->on == on));
                        debugFree( un, -300161 );
                        if (m == 0 && glip4) {
                                on->primary_ip4 = 0;
                                addr_to_str(0, on->primary_ip4_str);
                        }

                } else if (op == TLV_TEST) {

                        if (avl_find(&global_uhna_tree, &key))
                                return TLVS_BLOCKED;

                } else if (op == TLV_ADD) {

                        struct uhna4_node *un = debugMalloc( sizeof(struct uhna4_node),-300162 );
                        memset(un, 0, sizeof (struct uhna4_node));
                        memcpy(&un->key, &key, sizeof ( struct uhna4_key));
                        ASSERTION( -500359, (!avl_find(&global_uhna_tree, &key)));
                        un->on = on;
                        avl_insert(&global_uhna_tree, un, -300163);

                        if (m == 0 && glip4) {
                                on->primary_ip4 = key.glip4;
                                addr_to_str(on->primary_ip4, on->primary_ip4_str);
                        }

                } else if ( op == TLV_DEBUG ) {

                        dbg_printf(cn, "    %s %s/%d metric %d\n", glip4 ? "glip4:" : "uhna4:",
                                ipStr(key.glip4), key.prefix_len, ntohl(key.metric_be) );

                } else {
                        assertion( -500369, (NO));
                }
        }

        return TLVS_SUCCESS;
}




void configure_hna ( IDM_T del, struct uhna4_key* key, struct orig_node *on ) {

        struct uhna4_node *un = avl_find_item( &global_uhna_tree, key );

        paranoia( -500236, ((del && !un) || (!del && un)) );

        // update uhna_tree:
        if ( del ) {
                
                paranoia(-500234, (on != un->on));
                avl_remove(&global_uhna_tree, &un->key, -300212);
                ASSERTION( -500233, (!avl_find( &global_uhna_tree, key)) ); // there should be only one element with this key

                if ( !on)
                        avl_remove(&local_uhna_tree, &un->key, -300213);

        } else {

                un = debugMalloc( sizeof (struct uhna4_node), -300090 );
                un->key = *key;
                un->on = on;
                avl_insert(&global_uhna_tree, un, -300149);

                if (!on)
                        avl_insert(&local_uhna_tree, un, -300150);
        }

        if ( on ) {

                // update network routes:
                if ( del) {
                        configure_route(key->glip4, key->prefix_len, ntohl(key->metric_be),
                                0, my_orig_node.primary_ip4,
                                0, 0,
                                RT_TABLE_NETWORKS, RTN_UNICAST, DEL, TRACK_OTHER_HNA);
                } else {
                        ASSERTION(-500239, (avl_find( &link_dev_tree, &on->router_key)));

                        configure_route(key->glip4, key->prefix_len, ntohl(key->metric_be),
                                on->router_key.llip4, my_orig_node.primary_ip4,
                                on->router_key.dev->index, on->router_key.dev->name,
                                RT_TABLE_NETWORKS, RTN_UNICAST, ADD, TRACK_OTHER_HNA);
                }

        } else {
                // update my description:
                update_my_description_adv();

                // update throw routes:
                configure_route(key->glip4, key->prefix_len, 0, 0, 0, 0, "unknown", RT_TABLE_HOSTS, RTN_THROW, del, TRACK_MY_HNA);
                configure_route(key->glip4, key->prefix_len, 0, 0, 0, 0, "unknown", RT_TABLE_NETWORKS, RTN_THROW, del, TRACK_MY_HNA);
                configure_route(key->glip4, key->prefix_len, 0, 0, 0, 0, "unknown", RT_TABLE_TUNNEL, RTN_THROW, del, TRACK_MY_HNA);
        }


        if ( del)
                debugFree(un, -300089);

}

STATIC_FUNC
int32_t opt_hna ( uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn ) {

	uint32_t ip;
	int32_t mask;
        uint32_t metric = 0;
        struct uhna4_key key;

	char new[30];

	if ( cmd == OPT_ADJUST  ||  cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {

		dbgf( DBGL_CHANGES, DBGT_INFO, "diff %d cmd %s  save %d  opt %s  patch %s",
		        patch->p_diff, opt_cmd2str[cmd], _save, opt->long_name, patch->p_val);


		if ( patch->p_val[0] >= '0'  &&  patch->p_val[0] <= '9' ) {

			// the unnamed UHNA
                        dbgf(DBGL_CHANGES, DBGT_INFO, "unnamed UHNA diff %d cmd %s  save %d  opt %s  patch %s",
                                patch->p_diff, opt_cmd2str[cmd], _save, opt->long_name, patch->p_val);

			if ( str2netw( patch->p_val, &ip, '/', cn, &mask, 32 ) == FAILURE )
				return FAILURE;

			sprintf( new, "%s/%d", ipStr( validate_net_mask( ip, mask, 0 ) ), mask );
			set_opt_parent_val( patch, new );

			if ( cmd == OPT_ADJUST )
				return SUCCESS;

		} else {

			// the named UHNA

			if ( adj_patched_network( opt, patch, new, &ip, &mask, cn ) == FAILURE )
				return FAILURE;

			if ( cmd == OPT_ADJUST )
				return SUCCESS;

			if ( patch->p_diff == NOP ) {

				// change network and netmask parameters of an already configured and named HNA

				char old[30];

				// 1. check if announcing the new HNA would not block,
				if ( check_apply_parent_option( ADD, OPT_CHECK, NO, opt, new, cn ) == FAILURE )
					return FAILURE;

				if ( get_tracked_network( opt, patch, old, &ip, &mask, cn ) == FAILURE )
					return FAILURE;

				// 3. remove the old HNA and hope to not mess it up...
                                set_uhna4_key(&key, mask, ip, metric);

                                if ( cmd == OPT_APPLY )
                                        configure_hna(DEL, &key, NULL);


			}

			// then continue with the new HNA
			if ( str2netw( new , &ip, '/', cn, &mask, 32 ) == FAILURE )
				return FAILURE;
                }

                set_uhna4_key(&key, mask, ip, metric);

                struct uhna4_node *un;

                if (patch->p_diff != DEL && (un = (avl_find_item(&global_uhna_tree, &key)))) {

			dbg_cn( cn, DBGL_CHANGES, DBGT_ERR, "UHNA %s/%d metric %d already blocked by %s !",
                                ipStr(ip), mask, metric, (un->on ? un->on->primary_ip4_str : "myself"));

                        return FAILURE;
		}

		if ( cmd == OPT_APPLY )
                        configure_hna((patch->p_diff == DEL ? DEL : ADD), &key, NULL);



	} else if ( cmd == OPT_UNREGISTER ) {

                struct avl_node *an;

                while ((an = global_uhna_tree.root))
                        configure_hna(DEL, (struct uhna4_key*) AVL_NODE_KEY( &global_uhna_tree, an), NULL);

	}

	return SUCCESS;

}

STATIC_FUNC
int32_t opt_show_hnas ( uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn ) {


	if ( cmd == OPT_APPLY ) {

		dbg_printf( cn, "unicast HNA    metric  Originator      \n");

                struct avl_node *an = NULL;
                struct uhna4_node *un;
                uint16_t hna_count = 0;

                while ((un = (struct uhna4_node*) ((an = avl_iterate(&global_uhna_tree, an)) ? an->item : NULL))) {

                        paranoia(-500361, (un->on && !un->on->desc0));

                        dbg_printf(cn, "%15s/%-2d  %10d  %-15s %s \n",
                                ipStr(un->key.glip4), un->key.prefix_len, ntohl(un->key.metric_be),
                                un->on ? un->on->primary_ip4_str : "localhost",
                                un->on ? un->on->desc0->id.name : " ");

                        process_description_tlvs(un->on, NULL, TLV_DEBUG, cn);
                        hna_count++;
                }

		dbg_printf( cn, "\n" );
	}
	return SUCCESS;
}



STATIC_FUNC
struct opt_type hna_options[]= {
//     		ord parent long_name   shrt Attributes				*ival		min		max		default		*function

	{ODI,0,0,			0,  5,0,0,0,0,0,				0,		0,		0,		0,		0,
			0,		"\nHost and Network Announcement (HNA) options:"},

	{ODI,0,ARG_UHNA,	 	'u',5,A_PMN,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,		opt_hna,
			ARG_PREFIX_FORM,"perform host-network announcement (HNA) for defined ip range"},

	{ODI,ARG_UHNA,ARG_NETW,	'n',5,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,		opt_hna,
			ARG_NETW_FORM, 	"specify network of announcement"},

	{ODI,ARG_UHNA,ARG_MASK,	'm',5,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,		opt_hna,
			ARG_MASK_FORM, 	"specify network prefix of announcement"},


	{ODI,0,ARG_HNAS,		0,  5,A_PS0,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0, 		opt_show_hnas,
			0,		"show HNAs of other nodes\n"}

};




STATIC_FUNC
void hna_cleanup( void ) {

}


STATIC_FUNC
int32_t hna_init( void ) {

	register_options_array( hna_options, sizeof( hna_options ) );

	return SUCCESS;
}



struct plugin_v2 *hna_get_plugin_v2( void ) {

	static struct plugin_v2 hna_plugin;
	memset( &hna_plugin, 0, sizeof ( struct plugin_v2 ) );

	hna_plugin.plugin_version = PLUGIN_VERSION_02;
	hna_plugin.plugin_name = "bmx_hna_plugin";
	hna_plugin.plugin_size = sizeof ( struct plugin_v2 );
        hna_plugin.plugin_bmx_revision = REVISION_VERSION;
        hna_plugin.plugin_bmx_version = SOURCE_VERSION;
	hna_plugin.cb_init = hna_init;
	hna_plugin.cb_cleanup = hna_cleanup;

        return &hna_plugin;
}


