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

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if.h>     /* ifr_if, ifr_tun */
#include <linux/rtnetlink.h>
#include <time.h>

#include "bmx.h"
#include "msg.h"
#include "hna.h"
#include "plugin.h"
#include "schedule.h"
#include "route.h"

#define DEF_HELLO_IVAL 500
#define MIN_HELLO_IVAL 10
#define MAX_HELLO_IVAL 10000
#define ARG_HELLO_IVAL "hello_interval"



int32_t my_pws = DEF_PWS;

int32_t local_lws = DEF_LWS;

int32_t local_rtq_lounge = DEF_RTQ_LOUNGE;

int32_t my_path_lounge = DEF_PATH_LOUNGE;

int32_t dad_to = DEF_DAD_TO;

int32_t my_ttl = DEF_TTL;

int32_t wl_clones = DEF_WL_CLONES;

int32_t my_path_hystere = DEF_PATH_HYST;

int32_t my_rcnt_hystere = DEF_RCNT_HYST;

int32_t my_rcnt_pws = DEF_RCNT_PWS;

int32_t my_rcnt_fk = DEF_RCNT_FK;

int32_t my_late_penalty = DEF_LATE_PENAL;

static int32_t drop_2hop_loop = DEF_DROP_2HLOOP;


static int32_t Asocial_device = DEF_ASOCIAL;


int32_t asym_weight = DEF_ASYM_WEIGHT;
int32_t sym_weight = DEF_SYM_WEIGHT;

static int32_t asym_exp = DEF_ASYM_EXP;

int32_t my_hop_penalty = DEF_HOP_PENALTY;


static int32_t ogi_pwrsave = MIN_OGM_INTERVAL;


static int32_t purge_to = DEF_PURGE_TO;


void* FAILURE_POINTER = &FAILURE_POINTER;

static int8_t stop = 0;

static struct timeval start_time_tv;
static struct timeval ret_tv, new_tv, diff_tv, acceptable_m_tv, acceptable_p_tv, max_tv = {0,(2000*MAX_SELECT_TIMEOUT_MS)};


uint32_t My_pid = 0;

uint32_t bmx_time = 0;
uint32_t bmx_time_sec = 0;

uint8_t on_the_fly = NO;

uint32_t s_curr_avg_cpu_load = 0;

struct dev_node *primary_if = NULL;


struct metric_algo link_metric_algo[SQR_RANGE];



struct orig_node my_orig_node;


AVL_TREE(dev_ip4_tree, struct dev_node, ip4_addr);
AVL_TREE(dev_name_tree, struct dev_node, name);

AVL_TREE(link_tree, struct link_node, llip4);
AVL_TREE(blacklisted_tree, struct black_node, dhash);

AVL_TREE(link_dev_tree, struct link_dev_node, key);

AVL_TREE(neigh_tree, struct neigh_node, nnkey);

AVL_TREE(dhash_tree, struct dhash_node, dhash);
AVL_TREE(dhash_invalid_tree, struct dhash_node, dhash);
LIST_SIMPEL( dhash_invalid_plist, struct plist_node, list );

AVL_TREE(orig_tree, struct orig_node, id);
AVL_TREE(blocked_tree, struct orig_node, id);


/*
STATIC_FUNC
void purge_neigh_node( struct link_node *ln, struct dhash_node *dhn );
*/

/***********************************************************
 Data Infrastructure
 ************************************************************/



void blacklist_neighbor(struct packet_buff *pb)
{

        dbgf(DBGL_SYS, DBGT_ERR, "%s via %s", pb->neigh_str, pb->iif->name);
}


IDM_T blacklisted_neighbor(struct packet_buff *pb, struct description_hash *dhash)
{

        dbgf_all(DBGT_INFO, "%s via %s", pb->neigh_str, pb->iif->name);
        return NO;
}


IDM_T validate_metric_algo(struct metric_algo *ma, struct ctrl_node *cn)
{

        if (ma->sqn_window <= ma->sqn_steps) {

                dbg_cn(cn, DBGL_SYS, DBGT_ERR, "SQN: window=%d MUST be greater than steps=%d",
                        ma->sqn_window, ma->sqn_steps);

        } else if (ma->sqn_window <= ma->sqn_lounge) {

                dbg_cn(cn, DBGL_SYS, DBGT_ERR, "SQN: window=%d MUST BE greater than lounge=%d",
                        ma->sqn_window, ma->sqn_lounge);

        } else if (ma->sqn_window % ma->sqn_steps) {

                dbg_cn(cn, DBGL_SYS, DBGT_ERR, "SQN: window=%d MUST BE multiple of steps=%d",
                        ma->sqn_window, ma->sqn_steps);

        } else if (ma->sqn_lounge % ma->sqn_steps) {

                dbg_cn(cn, DBGL_SYS, DBGT_ERR, "SQN: lounge=%d MUST BE multiple of steps=%d",
                        ma->sqn_lounge, ma->sqn_steps);
        } else {

                return SUCCESS;
        }

        return FAILURE;
}


uint32_t update_metric(struct metric_record *mr, struct metric_algo *ma, SQN_T sqn_in, SQN_T sqn_max, uint32_t probe)
{

        dbgf_all( DBGT_INFO,
                "sqn_in %d sqn_max %d probe %u "
                "metric_algo: mask 0x%X steps %d window %d lounge %d metric_record: clr %d, set %d val %u",
                sqn_in, sqn_max, probe,
                ma->sqn_mask, ma->sqn_steps, ma->sqn_window, ma->sqn_lounge, mr->clr, mr->set, mr->val);


        ASSERTION(-500491, (ma->sqn_mask == (SQN_T) (0XFFFF << (bits_count(((SQN_T) ~(ma->sqn_mask)))))));
        ASSERTION(-500492, (ma->sqn_steps == (SQN_T) (0X0001 << (bits_count(((SQN_T) ~(ma->sqn_mask)))))));
        assertion(-500493, (ma->sqn_window > ma->sqn_steps));
        assertion(-500494, (ma->sqn_window > ma->sqn_lounge));
        assertion(-500495, (!(ma->sqn_window & ((SQN_T)~(ma->sqn_mask)))));
        assertion(-500496, (!(ma->sqn_lounge & ((SQN_T)~(ma->sqn_mask)))));
        assertion(-500497, (!(mr->clr & ((SQN_T) ~(ma->sqn_mask)))));

//        assertion(-500498, (probe >= ma->sqn_window * ma->sqn_steps));      // may cause zero metric (which is ok)
//        assertion(-500499, (!(probe % (ma->sqn_window * ma->sqn_steps))));  // may cause slightly unfair metric
        assertion( -500500, (probe <= ma->metric_max));

        sqn_max &= ma->sqn_mask;
        SQN_T sqn_min = sqn_max - ma->sqn_lounge;
        SQN_T sqn_low_boundary = sqn_min + ma->sqn_steps - ma->sqn_window;
        SQN_T i;


        // first purge out-of-lounge positioned records:

        if (((SQN_T) (mr->clr - sqn_low_boundary)) < (ma->sqn_window - ma->sqn_steps)) {
                // mr->clr within A:
                SQN_T sqn_purge = sqn_min - mr->clr;
                SQN_T metric_purge = sqn_purge / ma->sqn_steps;
                mr->clr = sqn_min;

                assertion(-500500, (((SQN_T) (metric_purge - 1)) < ((ma->sqn_window / ma->sqn_steps) - 1)));

                for (i = 0; i < metric_purge; i++)
                        mr->val -= (mr->val / ma->regression);


        } else if (((SQN_T) (mr->clr - sqn_min)) <= ma->sqn_lounge) {

                // mr->clr within B: FINE!

        } else {

                // mr->clr out of any range:
                if ( mr->clr ) {
                        dbgf(DBGL_SYS, DBGT_ERR,
                                "sqn_in %d sqn_max %d probe %u "
                                "metric_algo: mask 0x%X steps %d window %d lounge %d metric_record: clr %d, set %d val %u",
                                sqn_in, sqn_max, probe,
                                ma->sqn_mask, ma->sqn_steps, ma->sqn_window, ma->sqn_lounge, mr->clr, mr->set, mr->val);
                }
                
                mr->clr = sqn_min;
                mr->val = 0;
        }


        if (!probe)
                return mr->val;

        // then update the metric:

        if (((SQN_T) (sqn_in - sqn_min)) < (ma->sqn_lounge + ma->sqn_steps)) {

                // sqn_in within B:

//                if (((SQN_T) ((mr->set) - sqn_min)) >= (ma->sqn_lounge + ma->sqn_steps)) {
                if (((SQN_T) ((mr->set & ma->sqn_mask) - sqn_min)) >= (ma->sqn_lounge + ma->sqn_steps)) {

                        // mr->set out of B (fix maybe illegal mr->set): then set to mr->clr - sqn_steps
                        mr->set = sqn_min - ma->sqn_steps;
                }


                if ((((sqn_in & ma->sqn_mask) == (mr->set & ma->sqn_mask)))) {

                        // sqn_in already set !

                } else if (((SQN_T) ((sqn_in & ma->sqn_mask)-(mr->set & ma->sqn_mask))) <= ma->sqn_lounge + ma->sqn_steps) {

                        // sqn_in > mr->set:

                        SQN_T sqn_purge = ((sqn_in & ma->sqn_mask)-(mr->clr & ma->sqn_mask));
                        SQN_T metric_purge = sqn_purge / ma->sqn_steps;

                        for (i = 0; i < metric_purge; i++)
                                mr->val -= (mr->val / ma->regression);

                        mr->val += (((((SQN_T) (sqn_in & ~(ma->sqn_mask))) + 1) * (probe / ma->regression)) / ma->sqn_steps);

                        mr->set = mr->clr = sqn_in & ma->sqn_mask;

                        uint64_t add = ((((SQN_T) (sqn_in & ~(ma->sqn_mask))) * probe) + (rand_num(probe - 1))) / ma->metric_max;

                        assertion(-500501, (add <= ((SQN_T) (sqn_in & ~(ma->sqn_mask)))));

                        mr->set += add;


                } else {

                        dbgf(DBGL_CHANGES, DBGT_WARN,
                                "sqn_in %d sqn_max %d probe %u "
                                "metric_algo: mask 0x%X steps %d window %d lounge %d metric_record: clr %d, set %d val %u",
                                sqn_in, sqn_max, probe,
                                ma->sqn_mask, ma->sqn_steps, ma->sqn_window, ma->sqn_lounge, mr->clr, mr->set, mr->val);
                        // impossible ??    assertion(-500502, (0));
                }
        }

        assertion(-500503, (mr->val <= ma->metric_max));
        return mr->val;
}





STATIC_FUNC
void assign_best_rtq_link(struct neigh_node *nn)
{
	struct list_node *lndev_pos;
        struct link_dev_node *lndev_best = NULL;
        struct link_node *ln;
        struct avl_node *an = NULL;

        assertion( -500451, (nn));

        dbgf_all( DBGT_INFO, "%s", nn->dhn->on->id.name);

        while ((ln = avl_iterate_item(&nn->link_tree, &an))) {

                list_for_each(lndev_pos, &ln->lndev_list)
                {
                        struct link_dev_node *lndev = list_entry(lndev_pos, struct link_dev_node, list);

                        if (!lndev_best ||
                                lndev->mr[SQR_RTQ].val > lndev_best->mr[SQR_RTQ].val ||
                                GREAT_U32(lndev->rtq_time_max, lndev_best->rtq_time_max)
                                )
                                lndev_best = lndev;

                }

        }
        assertion( -500406, (lndev_best));

        nn->best_rtq = lndev_best;

}



//BMX3 (done)
STATIC_FUNC
void free_neigh_node(struct neigh_node *nn)
{
        paranoia(-500321, (nn->link_tree.items));

        dbgf(DBGL_SYS, DBGT_INFO," ");

        avl_remove(&neigh_tree, &nn->nnkey, -300196);
        iid_purge_repos(&nn->neighIID4x_repos);
        debugFree(nn, -300129);
}


/*
 * merging dhn->neigh into ln->neigh
 * keeping ln->neigh and dhn
 * purging ln->neigh->dhn and dhn->neigh
 */
//BMX3 (done)
STATIC_FUNC
struct neigh_node *merge_neigh_nodes(struct link_node *ln, struct dhash_node * dhn)
{
        struct neigh_node *neigh = ln->neigh;

        dbgf(DBGL_SYS, DBGT_ERR, "Neigh restarted ?!! purging %s %jX, keeping %s %jX",
                neigh->dhn->on->desc0->id.name, neigh->dhn->on->desc0->id.rand.u64[0],
                dhn->on->desc0->id.name, dhn->on->desc0->id.rand.u64[0]);

        if (dhn->neigh) {
                struct neigh_node *del_neigh = dhn->neigh;

                dbgf(DBGL_SYS, DBGT_ERR, "Merging neigh_nodes, purging %d neighIID4x entries ",
                        del_neigh->neighIID4x_repos.tot_used);

                assertion(-500406, (del_neigh->link_tree.items));

                struct avl_node *an;
                while ((an = del_neigh->link_tree.root)) {

                        struct link_node * mv_ln = an->item;

                        ASSERTION(-500408, (!avl_find(&neigh->link_tree, &mv_ln->llip4)));
                        assertion(-500409, (mv_ln != ln));

                        avl_insert(&neigh->link_tree, mv_ln, -300140);
                        mv_ln->neigh = neigh;
                        avl_remove(&del_neigh->link_tree, &mv_ln->llip4, -300199);
                }

                free_neigh_node(del_neigh);
        }

        neigh->dhn->neigh = NULL;
        invalidate_dhash_node(neigh->dhn);
        neigh->dhn = dhn;
        dhn->neigh = neigh;

        return neigh;
}


//BMX3 (done)
STATIC_FUNC
struct neigh_node * create_neigh_node(struct link_node *ln, struct dhash_node * dhn)
{
        assertion( -500400, ( ln && !ln->neigh && dhn && !dhn->neigh ) );

        struct neigh_node *nn = debugMalloc(sizeof ( struct neigh_node), -300131);

        memset(nn, 0, sizeof ( struct neigh_node));

        AVL_INIT_TREE(nn->link_tree, struct link_node, llip4);

        avl_insert(&nn->link_tree, ln, -300172);

        nn->dhn = dhn;

        nn->nnkey = nn;
        avl_insert(&neigh_tree, nn, -300141);

        dhn->neigh = ln->neigh = nn;

        return nn;
}


//BMX3 (done)
IDM_T update_neigh_node(struct link_node *ln, struct dhash_node *dhn, IID_T neighIID4neigh)
{
        struct neigh_node *neigh = NULL;

        dbgf_all( DBGT_INFO, "neigh %s  neighIID4neigh %d  dhn->orig %s",
                ln->llip4_str, neighIID4neigh, dhn->on->desc0->id.name);

        assertion(-500389, (ln && neighIID4neigh > IID_RSVD_MAX));
        assertion(-500390, (dhn && dhn->on));

        if (ln->neigh) {

                assertion(-500405, (ln->neigh->dhn && ln->neigh->dhn->on ));
                assertion(-500391, (ln->neigh->dhn->neigh == ln->neigh));
                ASSERTION(-500392, (avl_find(&ln->neigh->link_tree, &ln->llip4)));

                if (ln->neigh == dhn->neigh) {

                        assertion(-500393, (ln->neigh->dhn == dhn));

//always if new dhash:                        assertion(-500450, 0); //this never happen! or ?

                        neigh = ln->neigh;


                } else {

                        neigh = merge_neigh_nodes( ln, dhn);

                }

        } else {

                if ( dhn->neigh ) {

                        assertion(-500394, (dhn->neigh->dhn == dhn));
                        assertion(-500395, (dhn->neigh->link_tree.items));
                        ASSERTION(-500396, (!avl_find(&dhn->neigh->link_tree, &ln->llip4)));

                        neigh = ln->neigh = dhn->neigh;
                        avl_insert(&neigh->link_tree, ln, -300173);

                } else {

                        neigh = create_neigh_node( ln, dhn );

                }

        }

        assign_best_rtq_link(neigh);

        return update_neighIID4x_repository(neigh, neighIID4neigh, neigh->dhn);
}


STATIC_FUNC
struct link_dev_node *get_link_dev_node(struct link_node *ln, struct dev_node *dev)
{
	struct list_node *lndev_pos;
	struct link_dev_node *lndev;

	list_for_each( lndev_pos, &ln->lndev_list ) {

		lndev = list_entry( lndev_pos, struct link_dev_node, list );

		if ( lndev->key.dev == dev )
			return lndev;
	}

	lndev = debugMalloc( sizeof( struct link_dev_node ), -300023 );

	memset( lndev, 0, sizeof( struct link_dev_node ) );

	lndev->key.dev = dev;
        lndev->key.llip4 = ln->llip4;

	dbgf_all( DBGT_INFO, "creating new lndev %16s %10s %s",
	      ipStr(ln->llip4), dev->name, dev->ip4_str );

        list_add_tail(&ln->lndev_list, &lndev->list);

        ASSERTION( -500489, !avl_find( &link_dev_tree, &lndev->key));

        avl_insert( &link_dev_tree, lndev, -300220 );

        lndev->link = ln;

	return lndev;
}

STATIC_FUNC
struct link_node *get_link_node(uint32_t llip4)
{

	dbgf_all( DBGT_INFO, "%s", ipStr(llip4) );

        paranoia(-500210, !llip4);

        struct link_node *ln = avl_find_item(&link_tree, &llip4);

        if (!ln) {

                ln = debugMalloc(sizeof (struct link_node), -300024);
                memset(ln, 0, sizeof (struct link_node));

                LIST_INIT_HEAD(ln->lndev_list, struct link_dev_node, list);

                ln->llip4 = llip4;

                addr_to_str(llip4, ln->llip4_str);

                avl_insert(&link_tree, ln, -300147);
        }

        return ln;
}

void update_link_node(struct link_node *ln, struct dev_node *iif, SQN_T sqn, SQN_T sqn_max, uint8_t sqr, uint32_t probe)
{
//        uint8_t lounge_size = (sqr == SQR_RQ) ? RQ_LINK_LOUNGE : local_rtq_lounge;

        struct list_node *lndev_pos;
        struct link_dev_node *lndev, *this_lndev = NULL;

        list_for_each(lndev_pos, &ln->lndev_list)
        {
                lndev = list_entry(lndev_pos, struct link_dev_node, list);

                if (lndev->key.dev == iif) {

                        this_lndev = lndev;

                } else {

//                        update_lounged_metric(0, lounge_size, sqn, sqn_max, &lndev->sqr[sqr], local_lws);

                        update_metric(&lndev->mr[sqr], &link_metric_algo[sqr], sqn, sqn_max, 0);

                }

        }

        if (this_lndev) {

//                update_lounged_metric(probe, lounge_size, sqn, sqn_max, &this_lndev->sqr[sqr], local_lws);
                
                update_metric(&this_lndev->mr[sqr], &link_metric_algo[sqr], sqn, sqn_max, probe);

                if (probe && sqr == SQR_RTQ) {

                        this_lndev->rtq_time_max = bmx_time;

                        if (
                                ln->neigh &&
                                (!ln->neigh->best_rtq ||
                                ln->neigh->best_rtq->mr[SQR_RTQ].val <= this_lndev->mr[SQR_RTQ].val)) {

                                ln->neigh->best_rtq = this_lndev;
                        }
                }
        }

        if (probe && sqr == SQR_RQ) {
                ln->rq_time_max = bmx_time;
                ln->rq_sqn_max = sqn;
        }

        dbgf_all(DBGT_INFO, "%s dev %s",
                ipStr(ln->llip4), this_lndev ? this_lndev->key.dev->name : "???");

}



STATIC_FUNC
void purge_link_node(uint32_t only_llip4, struct dev_node *only_dev, IDM_T only_expired)
{
        struct avl_node *an;
        struct link_node *ln;
        uint32_t itip4 = 0;

        dbgf_all( DBGT_INFO, "%s %s %s only_expired",
                ipStr(only_llip4), only_dev ? only_dev->name : "---", only_expired ? " " : "not");

        while ((an = (only_llip4 ? (avl_find(&link_tree, &only_llip4)) : (avl_next(&link_tree, &itip4)))) && (ln = an->item)) {

                struct list_node *pos, *tmp, *prev = (struct list_node *) & ln->lndev_list;
                struct neigh_node *nn = ln->neigh;
                IDM_T removed_lndev = NO;

                itip4 = ln->llip4;

                list_for_each_safe(pos, tmp, &ln->lndev_list)
                {
                        struct link_dev_node *lndev = list_entry(pos, struct link_dev_node, list);

                        if ((!only_dev || only_dev == lndev->key.dev) &&
                                (!only_expired || (((uint32_t) (bmx_time - lndev->pkt_time_max)) > (uint32_t) purge_to))) {

                                dbgf(DBGL_CHANGES, DBGT_INFO, "purging lndev %16s %10s %s",
                                        ipStr(ln->llip4), lndev->key.dev->name, lndev->key.dev->ip4_str);

                                list_del_next(&ln->lndev_list, prev);
                                avl_remove(&link_dev_tree, &lndev->key, -300221);
                                debugFree(pos, -300044);
                                removed_lndev = YES;

                        } else {
                                prev = pos;
                        }
                }

                assertion(-500323, (only_dev || only_expired || ln->lndev_list.items==0));

                if (!ln->lndev_list.items) {

                        dbgf(DBGL_CHANGES, DBGT_INFO, "purging: %s %s", ipStr(itip4), only_dev ? only_dev->name : "???");

                        if (nn) {

                                avl_remove(&nn->link_tree, &ln->llip4, -300198);

                                if (!nn->link_tree.items) {

                                        if (nn->dhn) {
                                                nn->dhn->neigh = NULL;
                                        }

                                        free_neigh_node(nn);
                                        nn = NULL;
                                }
                        }

                        avl_remove(&link_tree, &ln->llip4, -300193 );

                        debugFree( ln, -300045 );
                }

                if (nn && removed_lndev)
                        assign_best_rtq_link(nn);

                if ( only_llip4 )
                        break;
        }
}

struct dhash_node* create_dhash_node(struct description_hash *dhash, struct orig_node *on)
{

        struct dhash_node * dhn = debugMalloc(sizeof ( struct dhash_node), -300001);
        memset(dhn, 0, sizeof ( struct dhash_node));
        memcpy(&dhn->dhash, dhash, BMX_HASH0_LEN);
        avl_insert(&dhash_tree, dhn, -300142);

        dhn->myIID4orig = iid_new_myIID4x(dhn);

        on->updated_timestamp = bmx_time;
        dhn->on = on;
        on->dhn = dhn;

        dbgf_all(DBGT_INFO, "dhash %8X.. myIID4orig %d", dhn->dhash.h.u32[0], dhn->myIID4orig);

        return dhn;
}

STATIC_FUNC
void free_dhash_iid(struct dhash_node *dhn)
{
        struct avl_node *an;
        struct neigh_node *nn;

        iid_free(&my_iid_repos, dhn->myIID4orig);

        //reset all neigh_node->oid_repos[x]=dhn->mid4o entries
        for (an = NULL; (nn = avl_iterate_item(&neigh_tree, &an));) {

                iid_free_neighIID4x_by_myIID4x(&nn->neighIID4x_repos, dhn->myIID4orig);

        }

        debugFree(dhn, -300112);

}

STATIC_FUNC
 void purge_dhash_to_list( IDM_T purge_all ) {

        struct dhash_node *dhn;

        dbgf_all( DBGT_INFO, "%s", purge_all ? "purge_all" : "only_expired");

        while ((dhn = plist_get_first(&dhash_invalid_plist)) ) {

                if (purge_all || ((uint32_t) (bmx_time - dhn->referred_timestamp) > MIN_DHASH_TO)) {

                        dbgf_all( DBGT_INFO, "dhash %8X myIID4orig %d", dhn->dhash.h.u32[0], dhn->myIID4orig);

                        plist_rem_head(&dhash_invalid_plist);
                        avl_remove(&dhash_invalid_tree, &dhn->dhash, -300194);

                        free_dhash_iid(dhn);

                } else {
                        break;
                }
        }
}

STATIC_FUNC
void unlink_dhash_node(struct dhash_node *dhn)
{
        dbgf_all(DBGT_INFO, "dhash %8X myIID4orig %d", dhn->dhash.h.u32[0], dhn->myIID4orig);

        if (dhn->neigh) {

                struct avl_node *an;
                struct link_node *ln;

                while ((an = dhn->neigh->link_tree.root) && (ln = an->item)) {

                        dbgf_all(DBGT_INFO, "dhn->neigh->link_tree item %s", ln->llip4_str);

                        assertion(-500284, (ln->neigh == dhn->neigh));

                        ln->neigh = NULL;

                        avl_remove(&dhn->neigh->link_tree, &ln->llip4, -300197);
                }

                free_neigh_node(dhn->neigh);
                
                dhn->neigh = NULL;
        }

        if (dhn->on) {
                dhn->on->dhn = NULL;
                free_orig_node( dhn->on );
                dhn->on = NULL;
        }



        avl_remove(&dhash_tree, &dhn->dhash, -300195);

}


void free_dhash_node( struct dhash_node *dhn )
{
        dbgf(DBGL_SYS, DBGT_INFO, "dhash %8X myIID4orig %d", dhn->dhash.h.u32[0], dhn->myIID4orig);

        invalidate_dhash_node(dhn);
        return;

        unlink_dhash_node(dhn);

        free_dhash_iid(dhn);

}

void invalidate_dhash_node( struct dhash_node *dhn )
{

        dbgf_all( DBGT_INFO,
                "dhash %8X myIID4orig %d, my_iid_repository: used %d, inactive %d  min_free %d  max_free %d ",
                dhn->dhash.h.u32[0], dhn->myIID4orig,
                my_iid_repos.tot_used, dhash_invalid_tree.items+1, my_iid_repos.min_free, my_iid_repos.max_free);

        unlink_dhash_node(dhn); // will clear dhn->on

        avl_insert(&dhash_invalid_tree, dhn, -300168);
        plist_add_tail(&dhash_invalid_plist, dhn);
        dhn->referred_timestamp = bmx_time;


        //dhn->invalid=YES;
}






//BMX3 (done)
IDM_T update_neighIID4x_repository(struct neigh_node *neigh, IID_T neighIID4x, struct dhash_node *dhn)
{
        assertion(-500386, (neigh->dhn != my_orig_node.dhn));

        if (dhn == my_orig_node.dhn)
                neigh->neighIID4me = neighIID4x;

        if (dhn == neigh->dhn)
                neigh->neighIID4neigh = neighIID4x;

        return iid_set_neighIID4x(&neigh->neighIID4x_repos, neighIID4x, dhn->myIID4orig);
}


STATIC_FUNC
void purge_router_tree( struct orig_node *on, IDM_T purge_all )
{
        struct avl_node *an;
        struct link_key key;
        memset( &key, 0, sizeof(struct link_key));

        while ((an = avl_next(&on->router_tree, &key))) {

                struct router_node *rn = an->item;

                memcpy(&key, &rn->key, sizeof (struct link_key));

                if (purge_all || !avl_find(&link_dev_tree, &rn->key)) {
                        debugFree(rn, -300225);
                        avl_remove(&on->router_tree, &rn->key, -300226);
                }
        }
}

IDM_T update_orig_metrics(struct packet_buff *pb, struct orig_node *on, IID_T orig_sqn)
{
        dbgf_all( DBGT_INFO, "%s orig_sqn %d via neigh %s", on->id.name, orig_sqn,pb->neigh_str);

        struct router_node *rn_in = NULL;
        uint32_t metric_in, metric_best = 0;
        SQN_T mask = on->path_metric_algo.sqn_mask;
        struct link_key *key_in = &pb->lndev->key;

        if (on->blocked || (((SQN_T) (orig_sqn - on->ogm_sqn_min)) >= on->ogm_sqn_range))
                return FAILURE;

        SQN_T ogm_sqn_max_rcvd = MAX_SQ(on->ogm_sqn_max_rcvd, orig_sqn);

        if (((SQN_T) ((ogm_sqn_max_rcvd & mask) - (orig_sqn & mask))) > on->path_metric_algo.sqn_lounge ) {

                dbgf(DBGL_CHANGES, DBGT_WARN, "%s orig_sqn %d to old max_sqn %d via neigh %s",
                        on->id.name, orig_sqn, on->ogm_sqn_max_rcvd, pb->neigh_str);


                return FAILURE;
        }

        if (LESS_SQN((on->ogm_sqn_max_rcvd & mask), (orig_sqn & mask))) {

                for (;;) {
                        struct router_node *rn;
                        struct avl_node *an;
                        struct router_node *rn_best = NULL;
                        uint32_t metric_temp;
                        metric_best = 0;

                        for (an = NULL; (rn = avl_iterate_item(&on->router_tree, &an));) {

                                if (rn->key.dev == key_in->dev && rn->key.llip4 == key_in->llip4) {

                                        rn_in = rn;

                                } else {

                                        metric_temp = update_metric(&rn->mr, &on->path_metric_algo, 0, ogm_sqn_max_rcvd, 0);

                                        if (metric_best < metric_temp) {

                                                metric_best = metric_temp;
                                                rn_best = rn;
                                        }
                                }
                        }

                        if (rn_best && !avl_find(&link_dev_tree, &rn_best->key)) {
                                purge_router_tree(on, NO);
                                continue;
                        } else {
                                break;
                        }
                }

        } else {
                // already cleaned up, simple use last best_metric:

                metric_best = on->router_best_metric;

                rn_in = avl_find_item( &on->router_tree, key_in );
        }

        if (!rn_in) {
                rn_in = debugMalloc(sizeof (struct router_node), -300222);
                memset( rn_in, 0, sizeof(struct router_node));
                memcpy( &rn_in->key, &pb->lndev->key, sizeof(struct link_key));
                avl_insert(&on->router_tree, rn_in, -300223);
        }

        metric_in = update_metric(&rn_in->mr, &on->path_metric_algo, orig_sqn, ogm_sqn_max_rcvd, pb->lndev->mr[SQR_RTQ].val);


        if (metric_in > metric_best && GREAT_SQN(rn_in->mr.set & mask, on->ogm_sqn_to_be_send & mask)) {

                on->router_path_metric = metric_in;
                on->router_best_metric = metric_in;
                on->ogm_sqn_to_be_send = rn_in->mr.set;
                ogm_aggreg_pending++;

                if (memcmp(&on->router_key, &rn_in->key, sizeof (struct link_key))) {

                        struct link_dev_node *lndev_old = avl_find_item(&link_dev_tree, &on->router_key);

                        dbgf((!on->router_key.llip4 || lndev_old) ? DBGL_CHANGES : DBGL_SYS,
                                (!on->router_key.llip4 || lndev_old) ? DBGT_INFO : DBGT_ERR,
                                "changing router to %s %s via %s %s metric %d (prev %s %s)",
                                on->id.name, on->primary_ip4_str,
                                ipStr(rn_in ? rn_in->key.llip4 : 0), rn_in ? rn_in->key.dev->name : "---", metric_in,
                                ipStr(on->router_key.llip4), lndev_old ? on->router_key.dev->name : "---");

                        assertion(-500504, (!on->router_key.llip4 || lndev_old));

                        if (on->router_key.llip4) {
                                configure_route(on->primary_ip4, 32, 0, on->router_key.llip4, 0,
                                        on->router_key.dev->index, on->router_key.dev->name,
                                        RT_TABLE_HOSTS, RTN_UNICAST, DEL, TRACK_OTHER_HOST);
                        }

                        configure_route(on->primary_ip4, 32, 0, rn_in->key.llip4, my_orig_node.primary_ip4,
                                rn_in->key.dev->index, rn_in->key.dev->name,
                                RT_TABLE_HOSTS, RTN_UNICAST, ADD, TRACK_OTHER_HOST);

                        memcpy(&on->router_key, &rn_in->key, sizeof (struct link_key));
                }

        } else {
                on->router_best_metric = metric_best;
        }

        on->ogm_sqn_max_rcvd = ogm_sqn_max_rcvd;

        return SUCCESS;
}



void free_orig_node(struct orig_node *on)
{
        dbgf(DBGL_CHANGES, DBGT_INFO, "%s", on->primary_ip4_str);

        if ( on == &my_orig_node)
                return;

        if (on->router_key.llip4) {
                configure_route(on->primary_ip4, 32, 0, on->router_key.llip4, 0,
                        on->router_key.dev->index, on->router_key.dev->name,
                        RT_TABLE_HOSTS, RTN_UNICAST, DEL, TRACK_OTHER_HOST);
        }


        process_description_tlvs(on, NULL, TLV_DEL_TEST_ADD, NULL);


        if ( on->dhn ) {
                on->dhn->on = NULL;
                free_dhash_node(on->dhn);
        }

        purge_router_tree(on, YES);

        avl_remove(&orig_tree, &on->id, -300200);
        avl_remove(&blocked_tree, &on->id, -300201);

        debugFree( on->desc0, -300228 );
        debugFree( on, -300086 );
}




void purge_orig(struct dev_node *only_dev, IDM_T only_expired)
{

        dbgf_all( DBGT_INFO, "%s %s only expired",
                only_dev ? only_dev->name : "---", only_expired ? " " : "NOT");

        purge_link_node( 0, only_dev, only_expired );

        int i;
        for (i = IID_RSVD_MAX + 1; i < my_iid_repos.max_free; i++) {

                struct dhash_node *dhn;

                if ((dhn = my_iid_repos.arr.node[i]) && dhn->on) {

                        if ( only_dev ) {

                                //TODO: keep on and only remove route
                                if ( dhn->on->router_key.dev == only_dev)
                                        free_orig_node(dhn->on);

                        } else if (!only_expired || ((uint32_t) (bmx_time - dhn->referred_timestamp)) > (uint32_t) purge_to) {

                                free_orig_node(dhn->on);
                        }
                }
        }
}

struct dev_node * get_bif(char *dev)
{
        char dev_name[IFNAMSIZ];
        memset(dev_name, 0, IFNAMSIZ);

        strncpy(dev_name, dev, IFNAMSIZ - 1);

        return avl_find_item(&dev_name_tree, dev_name);

}


void rx_packet( struct packet_buff *pb )
{
        struct dev_node *dev;
        struct dev_node *iif = pb->iif;
        struct packet_header *hdr = (struct packet_header *) pb->packet_in;
        hdr->pkt_length = ntohs(hdr->pkt_length);
        hdr->pkt_dev_sqn = ntohs(hdr->pkt_dev_sqn);

        if (pb->pkt_buff_llip4 == iif->ip4_broad) {
                dbgf(DBGL_SYS, DBGT_WARN,
                        "drop OGM: %s via %s ignoring all packets with broadcast source IP",
                        ipStr(pb->pkt_buff_llip4), pb->iif->name);
                return;
        }

        if ((dev = avl_find_item(&dev_ip4_tree, &pb->pkt_buff_llip4))) {
                // mark own packets;
                pb->oif = iif;
        } else {
                pb->oif = NULL;
        }


	addr_to_str( pb->pkt_buff_llip4, pb->neigh_str );

	// immediately drop invalid packets...
	// we acceppt longer packets than specified by pos->size to allow padding for equal packet sizes
        if (    pb->total_length < (int) (sizeof (struct packet_header) + sizeof (struct frame_header)) ||
                hdr->pkt_length < (int) (sizeof (struct packet_header) + sizeof (struct frame_header)) ||
                hdr->bmx_version != COMPAT_VERSION ||
                hdr->pkt_length > pb->total_length || hdr->pkt_length > MAX_UDPD_SIZE) {

                goto process_packet_error_hdr;
        }

	dbgf_all( DBGT_INFO, "version? %i, reserved? %X, size? %i, sqn %d  rcvd udp_len %d via NB %s %s %s",
                hdr->bmx_version, hdr->bmx_capabilities, hdr->pkt_length, hdr->pkt_dev_sqn,
                pb->total_length, pb->neigh_str, iif->name, pb->unicast ? "UNICAST" : "BRC");


        if (!pb->oif) {

                iif->link_activity_timestamp = bmx_time;

        } else if (((SQN_T) (pb->oif->packet_sqn - hdr->pkt_dev_sqn)) > 2) {

                dbgf(DBGL_SYS, DBGT_WARN,
                        "DAD-Alert via dev %s Somebody is using my Link-Local Address %s pkt_sqn %d != %d!!!",
                        iif->name, pb->oif->ip4_str, hdr->pkt_dev_sqn, pb->oif->packet_sqn);

                goto process_packet_error_hdr;

        } else {
                return;
        }


        struct link_node *ln = get_link_node(pb->pkt_buff_llip4);

        if (ln->pkt_time_max && ln->pkt_sqn_max && ((SQN_T) (hdr->pkt_dev_sqn - ln->pkt_sqn_max)) > SQN_DAD_RANGE) {

                dbgf(DBGL_SYS, DBGT_WARN,
                        "NB %s (via %s) reinitialized (or DAD?!) pkt_sqn %d != %d! Reinitializing link_node",
                        pb->neigh_str, iif->name, hdr->pkt_dev_sqn, ln->pkt_sqn_max);

                purge_link_node(ln->llip4, NULL, NO);
                ASSERTION( -500213, !avl_find(&link_tree, &pb->pkt_buff_llip4 ) );
                ln = get_link_node(pb->pkt_buff_llip4);
        }

        ln->pkt_sqn_max = hdr->pkt_dev_sqn;
        ln->pkt_time_max = bmx_time;
        pb->ln = ln;
        pb->lndev = get_link_dev_node(ln, pb->iif);
        pb->lndev->pkt_time_max = bmx_time;


        dbgf_all( DBGT_INFO, "rcvd packet from %s size %d via dev %s",
                pb->neigh_str, hdr->pkt_length, iif->name);

        if (blacklisted_neighbor(pb, NULL))
                return;

        if (rx_frames(pb, hdr->pkt_data, hdr->pkt_length - sizeof (struct packet_header)) == SUCCESS)
                return;

process_packet_error_hdr:
        dbgf(DBGL_SYS, DBGT_WARN,
                "Drop (remaining) packet: rcvd problematic packet via NB %s %s"
                "(version? %i, reserved? %X, pkt_size? %i), rcvd udp_len % d My version is % d, max_udpd_size %d",
                pb->neigh_str, iif->name,
                hdr->bmx_version, hdr->bmx_capabilities, hdr->pkt_length, pb->total_length,
                COMPAT_VERSION, MAX_UDPD_SIZE);

        return;
}


/***********************************************************
 Runtime Infrastructure
************************************************************/

void upd_time( struct timeval *precise_tv ) {

	timeradd( &max_tv, &new_tv, &acceptable_p_tv );
	timercpy( &acceptable_m_tv, &new_tv );
	gettimeofday( &new_tv, NULL );

	if ( timercmp( &new_tv, &acceptable_p_tv, > ) ) {

		timersub( &new_tv, &acceptable_p_tv, &diff_tv );
		timeradd( &start_time_tv, &diff_tv, &start_time_tv );

		dbg( DBGL_SYS, DBGT_WARN,
		     "critical system time drift detected: ++ca %ld s, %ld us! Correcting reference!",
		     diff_tv.tv_sec, diff_tv.tv_usec );

                if ( diff_tv.tv_sec > CRITICAL_PURGE_TIME_DRIFT )
                        purge_orig(NULL, NO);

	} else 	if ( timercmp( &new_tv, &acceptable_m_tv, < ) ) {

		timersub( &acceptable_m_tv, &new_tv, &diff_tv );
		timersub( &start_time_tv, &diff_tv, &start_time_tv );

		dbg( DBGL_SYS, DBGT_WARN,
		     "critical system time drift detected: --ca %ld s, %ld us! Correcting reference!",
		     diff_tv.tv_sec, diff_tv.tv_usec );

                if ( diff_tv.tv_sec > CRITICAL_PURGE_TIME_DRIFT )
                        purge_orig(NULL, NO);

	}

	timersub( &new_tv, &start_time_tv, &ret_tv );

	if ( precise_tv ) {
		precise_tv->tv_sec = ret_tv.tv_sec;
		precise_tv->tv_usec = ret_tv.tv_usec;
	}

	bmx_time = ( (ret_tv.tv_sec * 1000) + (ret_tv.tv_usec / 1000) );
	bmx_time_sec = ret_tv.tv_sec;

}



char *get_human_uptime( uint32_t reference ) {
	//                  DD:HH:MM:SS
	static char ut[32]="00:00:00:00";

	sprintf( ut, "%2i:%i%i:%i%i:%i%i",
	         (((bmx_time_sec-reference)/86400)),
	         (((bmx_time_sec-reference)%86400)/36000)%10,
	         (((bmx_time_sec-reference)%86400)/3600)%10,
	         (((bmx_time_sec-reference)%3600)/600)%10,
	         (((bmx_time_sec-reference)%3600)/60)%10,
	         (((bmx_time_sec-reference)%60)/10)%10,
	         (((bmx_time_sec-reference)%60))%10
	       );

	return ut;
}


void wait_sec_msec( uint32_t sec, uint32_t msec ) {

	struct timeval time;

	//no debugging here because this is called from debug_output() -> dbg_fprintf() which may case a loop!
	//dbgf_all( DBGT_INFO, "%d sec %d msec...", sec, msec );

	time.tv_sec = sec + (msec/1000) ;
	time.tv_usec = ( msec * 1000 ) % 1000000;

	select( 0, NULL, NULL, NULL, &time );

	//update_bmx_time( NULL ); //this will cause critical system time drift message from the client
	//dbgf_all( DBGT_INFO, "bat_wait(): done");

	return;
}



int32_t rand_num( uint32_t limit ) {

	return ( limit == 0 ? 0 : rand() % limit );
}



int8_t terminating() {

	return stop != 0;

}


static void handler( int32_t sig ) {

	if ( !Client_mode ) {
		dbgf( DBGL_SYS, DBGT_ERR, "called with signal %d", sig);
	}

	printf("\n");// to have a newline after ^C

	stop = 1;
	cb_plugin_hooks( NULL, PLUGIN_CB_TERM );

}


/* counting bits based on http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetTable */

static unsigned char BitsSetTable256[256];

STATIC_FUNC
void init_set_bits_table256(void)
{
	BitsSetTable256[0] = 0;
	int i;
	for (i = 0; i < 256; i++)
	{
		BitsSetTable256[i] = (i & 1) + BitsSetTable256[i / 2];
	}
}

// count the number of true bits in v

uint8_t bits_count(uint32_t v)
{
	uint8_t c=0;
        uint32_t w = v;

	for (; v; v = v>>8 )
		c += BitsSetTable256[v & 0xff];

        dbgf_all( DBGT_INFO, "%8X, counted %d bits", w, c);
        
	return c;
}

uint8_t bit_get(uint8_t *array, uint16_t array_bit_size, uint16_t bit)
{
        bit = bit % array_bit_size;

        uint16_t byte_pos = bit / 8;
        uint8_t bit_pos = bit % 8;

        return (array[byte_pos] & (0x01 << bit_pos)) ? 1 : 0;
}

void bit_set(uint8_t *array, uint16_t array_bit_size, uint16_t bit, IDM_T value)
{
        bit = bit % array_bit_size;

        uint16_t byte_pos = bit / 8;
        uint8_t bit_pos = bit % 8;

        if (value)
                array[byte_pos] |= (0x01 << bit_pos);
        else
                array[byte_pos] &= ~(0x01 << bit_pos);

        assertion(-500415, (!value == !bit_get(array, array_bit_size, bit)));
}

/*
 * clears bit range between and including begin and end
 */
void bit_clear(uint8_t *array, uint16_t array_bit_size, uint16_t begin_bit, uint16_t end_bit)
{
        assertion(-500435, (array_bit_size % 8 == 0));

        if (((uint16_t) (end_bit - begin_bit)) >= (array_bit_size - 1)) {

                memset(array, 0, array_bit_size / 8);
                return;
        }
        
        begin_bit = begin_bit % array_bit_size;
        end_bit = end_bit % array_bit_size;

        uint16_t begin_byte = begin_bit/8;
        uint16_t end_byte = end_bit/8;
        uint16_t array_byte_size = array_bit_size/8;


        if (begin_byte != end_byte && ((begin_byte + 1) % array_byte_size) != end_byte)
                byte_clear(array, array_byte_size, begin_byte + 1, end_byte - 1);


        uint8_t begin_mask = ~(0xFF << (begin_bit%8));
        uint8_t end_mask = (0xFF >> ((end_bit%8)+1));

        if (begin_byte == end_byte) {

                array[begin_byte] &= (begin_mask | end_mask);

        } else {

                array[begin_byte] &= begin_mask;
                array[end_byte] &= end_mask;
        }
}

/*
 * clears byte range between and including begin and end
 */
void byte_clear(uint8_t *array, uint16_t array_size, uint16_t begin, uint16_t end)
{

        assertion(-500436, (array_size % 2 == 0));

        begin = begin % array_size;
        end = end % array_size;

        memset(array + begin, 0, end >= begin ? end + 1 - begin : array_size - begin);

        if ( begin > end)
                memset(array, 0, end + 1);


}

uint8_t is_zero(char *data, int len)
{
        int i;

        for (i = 0; i < len && !data[i]; i++);

        if ( i < len )
                return NO;

        return YES;
}



static int segfault = NO;
static int cleaning_up = NO;

static void segmentation_fault(int32_t sig)
{

        dbg(DBGL_SYS, DBGT_ERR, "SIGSEGV %d received, try cleaning up (%s-rv%d)...",
                sig, SOURCE_VERSION, REVISION_VERSION);

        if (!segfault) {

                segfault = YES;

                signal(SIGSEGV, SIG_DFL);


                if (!on_the_fly)
                        dbg(DBGL_SYS, DBGT_ERR,
                        "check up-to-dateness of bmx libs in default lib path %s or customized lib path defined by %s !",
                        BMX_DEF_LIB_PATH, BMX_ENV_LIB_PATH);


                if (!cleaning_up)
                        cleanup_all(CLEANUP_RETURN);

                dbg(DBGL_SYS, DBGT_ERR, "raising SIGSEGV again ...");
        }

        errno=0;
	if ( raise( SIGSEGV ) ) {
		dbg( DBGL_SYS, DBGT_ERR, "raising SIGSEGV failed: %s...", strerror(errno) );
        }
}


void cleanup_all(int status)
{

        if (status < 0) {
                dbg(DBGL_SYS, DBGT_ERR, "Terminating with error code %d ! Please notify a developer", status);
                segmentation_fault(1);
        }

        if (!cleaning_up) {

                dbgf_all(DBGT_INFO, "cleaning up (status %d)...", status);

                cleaning_up = YES;

                // first, restore defaults...

		stop = 1;

		cleanup_schedule();


                if (my_orig_node.dhn) {
                        my_orig_node.dhn->on = NULL;
                        free_dhash_node(my_orig_node.dhn);
                }

                avl_remove(&orig_tree, &(my_orig_node.id), -300203);

		purge_orig( NULL, NO );

		cleanup_plugin();

		cleanup_config();

		cleanup_route();

                cleanup_msg();

                purge_dhash_to_list(YES);


                while (dev_name_tree.items) {

                        struct dev_node *dev = dev_name_tree.root->item;

			if ( dev->active )
				dev_deactivate( dev );

                        avl_remove(&dev_name_tree, &dev->name, -300204);

                        debugFree(dev, -300046);

                }

		// last, close debugging system and check for forgotten resources...
		cleanup_control();

		checkLeak();

                dbgf_all( DBGT_ERR, "...cleaning up done");

                if (status == CLEANUP_SUCCESS) {

                        exit(EXIT_SUCCESS);

                } else if (status == CLEANUP_FAILURE) {

                        exit(EXIT_FAILURE);

                } else if (status == CLEANUP_RETURN) {

                        return;

                }

                exit(EXIT_FAILURE);
                dbg(DBGL_SYS, DBGT_ERR, "exit ignored!?");
        }

}











/***********************************************************
 Configuration data and handlers
************************************************************/


STATIC_FUNC
int32_t opt_show_origs(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

        int rq, tq, rtq;

        if ( cmd == OPT_APPLY ) {

                if (!strcmp(opt->long_name, ARG_ORIGINATORS)) {

                        dbg_printf(cn, "Originator:            rand             primary_ip       via                       "
                                "metric mid4o descSQN ogmSQN < max  lupd lref  pogi  pws\n");

                        struct avl_node *it = NULL;

                        while ((it = avl_iterate(&orig_tree, it))) {

                                struct orig_node *on = it->item;

                                struct link_dev_node *lndev = avl_find_item(&link_dev_tree, &on->router_key);

                                dbg_printf(cn, "%-22s %8X%8X %-15s  %-15s %-10s" "%6i %5d   %5d  %5d %5d %5d %4d %5d %4d\n",
                                        on->id.name, ntohl(on->id.rand.u32[0]), ntohl(on->id.rand.u32[1]),
                                        on->blocked ? "BLOCKED" : on->primary_ip4_str,
                                        ipStr(lndev ? lndev->key.llip4 : 0),
                                        lndev ? lndev->key.dev->name : "---",
                                        on->router_path_metric,
                                        on->dhn->myIID4orig, on->desc0_sqn,
                                        on->ogm_sqn_to_be_send,
                                        (on->ogm_sqn_min + on->ogm_sqn_range),
                                        (bmx_time - on->updated_timestamp) / 1000,
                                        (bmx_time - on->dhn->referred_timestamp) / 1000,
                                        ntohs(on->desc0->path_ogi), ntohs(on->desc0->path_window_size)
                                        );

                                //process_description_tlvs( on, NULL, TLV_DEBUG, cn );
                        }


                } else if (!strcmp(opt->long_name, ARG_STATUS)) {

                        dbg_printf(cn, "BMX %s-rv%d, %s, LWS %i, PWS %i, OGI %4ims, UT %s, CPU %d.%1d\n",
                                SOURCE_VERSION, REVISION_VERSION, my_orig_node.primary_ip4_str, local_lws, my_pws, my_ogm_interval,
                                get_human_uptime(0), s_curr_avg_cpu_load / 10, s_curr_avg_cpu_load % 10);


                } else if ( !strcmp( opt->long_name, ARG_LINKS ) ) {

                        dbg_printf(cn, "LinkLocalIP     viaIF      bestIF     primaryIP        RTQ   RQ   TQ   oid4m    lseq lvld\n");

                        struct avl_node *it = NULL;

                        while ((it = avl_iterate(&link_tree, it))) {

                                struct link_node *ln = it->item;
                                struct neigh_node *nn = ln->neigh;
                                struct orig_node *on = nn ? nn->dhn->on : NULL;

                                struct list_node *lndev_pos;

                                list_for_each( lndev_pos, &ln->lndev_list ) {
					struct link_dev_node *lndev = list_entry( lndev_pos, struct link_dev_node, list );

					rq = lndev->mr[SQR_RQ].val;
					tq = TQ_RATE( lndev, PROBE_RANGE); // tq_rate( lndev,  PROBE_RANGE );
					rtq = lndev->mr[SQR_RTQ].val;


					dbg_printf( cn, "%-15s %-10s %-10s %-15s %4i %4i %4i   %5d   %5i %4i\n",
                                                ipStr(ln->llip4),
                                                lndev->key.dev->name,
                                                ln->neigh && ln->neigh->best_rtq ? ln->neigh->best_rtq->key.dev->name : "---",
                                                on ? on->primary_ip4_str : "???",
                                                rtq , rq, tq,
                                                nn ? nn->neighIID4me : 0,
                                                ln->rq_sqn_max,
                                                (bmx_time - lndev->rtq_time_max) / 1000
                                                );

                                }

                        }

		} else {
			return FAILURE;
		}

		dbg_printf( cn, "\n" );
	}

	return SUCCESS;
}


STATIC_FUNC
int32_t opt_dev_show(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if ( cmd == OPT_APPLY ) {

                struct avl_node *it=NULL;
                struct dev_node *dev;
                while ((dev = avl_iterate_item(&dev_name_tree, &it))) {

			dbg_cn( cn, DBGL_ALL, DBGT_NONE, "%-10s %5d %8s %15s/%-2d  brc %-15s  SQN %5d  %14s  %8s  %11s",
			        dev->name,
                                dev->index,
			        !dev->active ? "-" :
			        ( dev->linklayer == VAL_DEV_LL_LO ? "loopback":
			          ( dev->linklayer == VAL_DEV_LL_LAN ? "ethernet":
			            ( dev->linklayer == VAL_DEV_LL_WLAN ? "wireless": "???" ) ) ),
			        dev->ip4_str,
			        dev->ip4_prefix_length,
			        ipStr(dev->ip4_broad),
			        dev->ogm_sqn,
			        dev->announce ? "announced" : "not announced",
			        dev->active ? "active" : "inactive",
			        dev == primary_if ? "primary" : "non-primary"
			      );

		}
	}
	return SUCCESS;
}
STATIC_FUNC
int32_t opt_dev(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	struct list_node *list_pos;
	struct dev_node *dev = NULL;

	struct dev_node test_bif;

	char *colon_ptr;

	dbgf_all( DBGT_INFO, "cmd: %s opt: %s  instance %s",
	          opt_cmd2str[cmd], opt->long_name, patch ? patch->p_val : "");

	if ( cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {

		if ( strlen(patch->p_val) >= IFNAMSIZ ) {
			dbg_cn( cn, DBGL_SYS, DBGT_ERR, "dev name MUST be smaller than %d chars", IFNAMSIZ );
			return FAILURE;
                }

                dev = get_bif( patch->p_val );

		if ( patch->p_diff == DEL ) {

			if ( dev  &&  primary_if == dev ) {

				dbg_cn( cn, DBGL_SYS, DBGT_ERR,
				        "primary interface %s %s can not be removed!",
				        dev->name, dev->ip4_str );

				return FAILURE;

			} else if ( dev  &&  cmd == OPT_APPLY ) {

				if ( dev->active )
					dev_deactivate( dev );

                                avl_remove( &dev_name_tree, &dev->name, -300205 );

                                debugFree(dev, -300048);

				return SUCCESS;


			} else if ( !dev ) {

				dbgf_cn( cn, DBGL_SYS, DBGT_ERR, "Interface does not exist!" );
				return FAILURE;
			}
		}

		if ( !dev ) {

			if ( cmd == OPT_APPLY ) {
                                int i;
                                dev = debugMalloc( sizeof(struct dev_node), -300002 );
                                memset(dev, 0, sizeof (struct dev_node));

                                if (!dev_name_tree.items)
					primary_if = dev;

                                snprintf(dev->name, wordlen(patch->p_val) + 1, "%s", patch->p_val);

                                avl_insert( &dev_name_tree, dev, -300144 );

                                for (i = 0; i < FRAME_TYPE_ARRSZ; i++) {
                                        LIST_INIT_HEAD(dev->tx_tasks_list[i], struct tx_task_node, list);
                                }

                                AVL_INIT_TREE( dev->tx_timestamp_tree, struct tx_timestamp_node, key );



                        } else {

				dev = &test_bif;
                                memset(dev, 0, sizeof (struct dev_node));
                                snprintf(dev->name, wordlen(patch->p_val) + 1, "%s", patch->p_val);

                        }

//                        bif->aggregation_out = bif->aggregation_out_buff;

			snprintf( dev->name_phy, wordlen(patch->p_val)+1, "%s", patch->p_val );

		/* if given interface is an alias record physical interface name*/
			if ( ( colon_ptr = strchr( dev->name_phy, ':' ) ) != NULL )
				*colon_ptr = '\0';

			dbgf_all( DBGT_INFO, "assign dev %s physical name %s", dev->name, dev->name_phy );

                        dev->ogm_sqn = rand_num(MAX_SQN);

                        dev->packet_sqn = rand_num(MAX_SQN);

		//	bif->aggregation_len = sizeof( struct bmx_pkt_hdr );


			// some configurable interface values - initialized to unspecified:
			dev->send_clones_conf  = -1;
			dev->antenna_diversity_conf = -1;
			dev->linklayer_conf = -1;
			dev->announce_conf = -1;

		}

		if ( cmd == OPT_CHECK )
			return SUCCESS;

		list_for_each( list_pos, &patch->childs_instance_list ) {

			struct opt_child *c = list_entry( list_pos, struct opt_child, list );

			int32_t val = c->c_val ? strtol( c->c_val , NULL , 10 ) : -1 ;

			if ( !strcmp( c->c_opt->long_name, ARG_DEV_CLONE ) ) {

				dev->send_clones_conf = val;

			} else if ( !strcmp( c->c_opt->long_name, ARG_DEV_ANTDVSTY ) ) {

				dev->antenna_diversity_conf = val;

			} else if ( !strcmp( c->c_opt->long_name, ARG_DEV_LL ) ) {

				dev->linklayer_conf = val;
				dev->hard_conf_changed = YES;

			} else if ( !strcmp( c->c_opt->long_name, ARG_DEV_ANNOUNCE ) ) {

				dev->announce_conf = val;
			}

			dev->soft_conf_changed = YES;

		}


	} else if ( cmd == OPT_POST  &&  opt  &&  !opt->parent_name ) {

		dev_check(); //will always be called whenever a parameter is changed (due to OPT_POST)

        }

	return SUCCESS;
}

STATIC_FUNC
int32_t opt_purge(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if ( cmd == OPT_APPLY)
                purge_orig(NULL, NO);

	return SUCCESS;
}


/*
STATIC_FUNC
int32_t opt_if_soft(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if ( cmd == OPT_APPLY )
		if_conf_soft_changed = YES;

	return SUCCESS;
}
*/

#ifdef WITHUNUSED

STATIC_FUNC
int32_t opt_if_hard(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if ( cmd == OPT_APPLY )
		if_conf_hard_changed = YES;

	return SUCCESS;
}
#endif


int32_t opt_update_description(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if ( cmd == OPT_APPLY )
		if_conf_soft_changed = YES;

	return SUCCESS;
}

STATIC_FUNC
int32_t opt_path_metric(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{


        if (cmd == OPT_CHECK || cmd == OPT_APPLY || cmd == OPT_REGISTER) {

                struct metric_algo test_algo;
                memset(&test_algo, 0, sizeof (struct metric_algo));

                test_algo.sqn_mask = ((SQN_T)(0xFFFF << DEF_OGM0_PQ_BITS));
                test_algo.sqn_steps = (0x01 << DEF_OGM0_PQ_BITS);
                test_algo.regression = my_pws / test_algo.sqn_steps / 2;
                test_algo.sqn_lounge = my_path_lounge;
                test_algo.sqn_window = my_pws;
                test_algo.metric_max = PROBE_RANGE;

                if (validate_metric_algo(&test_algo, cn) == FAILURE)
                        return FAILURE;

                if (cmd == OPT_APPLY || cmd == OPT_REGISTER)
                        memcpy(&(my_orig_node.path_metric_algo), &test_algo, sizeof (struct metric_algo));

        }

	if ( cmd == OPT_APPLY )
		if_conf_soft_changed = YES;

	return SUCCESS;
}

STATIC_FUNC
int32_t opt_link_metric(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        if (cmd == OPT_CHECK || cmd == OPT_APPLY || cmd == OPT_REGISTER) {

                struct metric_algo test_algo[SQR_RANGE];
                memset(test_algo, 0, SQR_RANGE * sizeof (struct metric_algo));

                test_algo[SQR_RTQ].sqn_mask = 0xFFFF;
                test_algo[SQR_RTQ].sqn_steps = 1;
                test_algo[SQR_RTQ].regression = local_lws / 2;
                test_algo[SQR_RTQ].sqn_lounge = local_rtq_lounge;
                test_algo[SQR_RTQ].sqn_window = local_lws;
                test_algo[SQR_RTQ].metric_max = PROBE_RANGE;

                if (validate_metric_algo(&(test_algo[SQR_RTQ]), cn) == FAILURE)
                        return FAILURE;

                test_algo[SQR_RQ].sqn_mask = 0xFFFF;
                test_algo[SQR_RQ].sqn_steps = 1;
                test_algo[SQR_RQ].regression = local_lws / 2;
                test_algo[SQR_RQ].sqn_lounge = RQ_LINK_LOUNGE;
                test_algo[SQR_RQ].sqn_window = local_lws;
                test_algo[SQR_RQ].metric_max = PROBE_RANGE;

                if (validate_metric_algo(&(test_algo[SQR_RQ]), cn) == FAILURE)
                        return FAILURE;

                if (cmd == OPT_APPLY || cmd == OPT_REGISTER)
                        memcpy(link_metric_algo, test_algo, SQR_RANGE * sizeof (struct metric_algo));


        }

        return SUCCESS;
}


static struct opt_type bmx_options[]=
{
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help

	{ODI,0,0,			0,  5,0,0,0,0,0,			0,		0,		0,		0,		0,
			0,		"\nProtocol options:"},

	{ODI,0,ARG_STATUS,		0,  5,A_PS0,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0, 		opt_show_origs,
			0,		"show status\n"},

	{ODI,0,ARG_ROUTES,		0,  5,A_PS0,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0, 		opt_show_origs,
			0,		"show routes\n"},

	{ODI,0,ARG_LINKS,		0,  5,A_PS0,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0, 		opt_show_origs,
			0,		"show links\n"},

	{ODI,0,ARG_ORIGINATORS,	        0,  5,A_PS0,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0, 		opt_show_origs,
			0,		"show originators\n"},

	{ODI,0,ARG_DEV,		        0,  5,A_PMN,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0, 		0,		0, 		opt_dev,
			"<interface-name>", "add or change device or its configuration, options for specified device are:"},

#ifndef LESS_OPTIONS
	{ODI,ARG_DEV,ARG_DEV_TTL,	't',5,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		MIN_TTL,	MAX_TTL,	DEF_TTL,	opt_dev,
			ARG_VALUE_FORM,	"set TTL of generated OGMs"},

	{ODI,ARG_DEV,ARG_DEV_CLONE,	'c',5,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		MIN_WL_CLONES,	MAX_WL_CLONES,	DEF_WL_CLONES,	opt_dev,
			ARG_VALUE_FORM,	"broadcast OGMs per ogm-interval with given probability (e.g. 200% will broadcast the same OGM twice)"},

	/* Antenna-diversity support for bmxd seems working but unfortunately there are few wireless drivers which support
	 * my understanding of the typical antenna-diversity implementation. This is what I hoped (maybe I am wrong):
	 * - The RX-antenna is detected on-the-fly on a per-packet basis by comparing
	 *   the rcvd signal-strength via each antenna during reception of the phy-preamble.
	 * - The TX-antenna is determined per MAC-address based on the last detected best RX-antenna for this MAC.
	 * - Broadcast packets should be send round-robin like via each enabled TX-antenna (e.g. alternating via ant1 and ant2). */
	{ODI,ARG_DEV,ARG_DEV_ANTDVSTY,   0,  5,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		1,		2,		1,		opt_dev,
			ARG_VALUE_FORM,	0/*"set number of broadcast antennas (e.g. for antenna-diversity use /d=2 /c=400 aggreg_interval=100)"*/},


	{ODI,ARG_DEV,ARG_DEV_ANNOUNCE,  'a',5,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		1,		DEF_DEV_ANNOUNCE,opt_dev,
			ARG_VALUE_FORM,	"disable/enable announcement of interface IP"},
#endif

	{ODI,ARG_DEV,ARG_DEV_LL,	 'l',5,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		VAL_DEV_LL_LAN,	VAL_DEV_LL_WLAN,0,		opt_dev,
			ARG_VALUE_FORM,	"manually set device type for linklayer specific optimization (1=lan, 2=wlan)"},

	{ODI,0,ARG_INTERFACES,	         0,  5,A_PS0,A_USR,A_DYI,A_ARG,A_ANY,	0,		0,		1,		0,		opt_dev_show,
			0,		"show configured interfaces"},

	{ODI,0,ARG_LWS,       	         0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&local_lws,	MIN_LWS, 	MAX_LWS,	DEF_LWS,	opt_link_metric,
			ARG_VALUE_FORM,	"set link window size (LWS) for link-quality calculation (link metric)"},

#ifndef LESS_OPTIONS

	{ODI,0,ARG_RTQ_LOUNGE,  	0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&local_rtq_lounge,MIN_RTQ_LOUNGE,MAX_RTQ_LOUNGE,DEF_RTQ_LOUNGE, opt_link_metric,
			ARG_VALUE_FORM, "set local LLS buffer size to artificially delay OGM processing for ordered link-quality calulation"},

	{ODI,0,ARG_PWS,         	0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_pws,	MIN_PWS, 	MAX_PWS,	DEF_PWS,	opt_path_metric,
			ARG_VALUE_FORM,	"set path window size (PWS) for end2end path-quality calculation (path metric)"},

	{ODI,0,ARG_PATH_LOUNGE,	0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_path_lounge,MIN_PATH_LOUNGE,MAX_PATH_LOUNGE,DEF_PATH_LOUNGE,        opt_path_metric,
			ARG_VALUE_FORM, "set default PLS buffer size to artificially delay my OGM processing for ordered path-quality calulation"},

	{ODI,0,ARG_PATH_HYST,   	0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_path_hystere,MIN_PATH_HYST,	MAX_PATH_HYST,	DEF_PATH_HYST,	opt_path_metric,
			ARG_VALUE_FORM,	"use hysteresis to delay route switching to alternative next-hop neighbors with better path metric"},


	{ODI,0,ARG_RCNT_PWS,	        0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_rcnt_pws,   MIN_RCNT_PWS,   MAX_RCNT_PWS,   DEF_RCNT_PWS,   opt_path_metric,
			ARG_VALUE_FORM, ""},

	{ODI,0,ARG_RCNT_HYST,   	0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_rcnt_hystere,MIN_RCNT_HYST,	MAX_RCNT_HYST,	DEF_RCNT_HYST,	opt_path_metric,
			ARG_VALUE_FORM,	"use hysteresis to delay fast-route switching to alternative next-hop neighbors with a recently extremely better path metric"},

	{ODI,0,ARG_RCNT_FK,	        0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_rcnt_fk,    MIN_RCNT_FK,    MAX_RCNT_FK,    DEF_RCNT_FK,    opt_path_metric,
			ARG_VALUE_FORM,	"configure threshold faktor for dead-path detection"},


	{ODI,0,ARG_DROP_2HLOOP, 	0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&drop_2hop_loop,MIN_DROP_2HLOOP,MAX_DROP_2HLOOP,DEF_DROP_2HLOOP,0,
			ARG_VALUE_FORM,	"drop OGMs received via two-hop loops"},


	{ODI,0,ARG_ASYM_EXP,		0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&asym_exp,	MIN_ASYM_EXP,	MAX_ASYM_EXP,	DEF_ASYM_EXP,	0,
			ARG_VALUE_FORM,	"ignore OGMs (rcvd via asymmetric links) with TQ^<val> to radically reflect asymmetric-links"},

	{ODI,0,"asocial_device",	0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&Asocial_device,MIN_ASOCIAL,	MAX_ASOCIAL,	DEF_ASOCIAL,	0,
			ARG_VALUE_FORM,	"disable/enable asocial mode for devices unwilling to forward other nodes' traffic"},

	{ODI,0,ARG_WL_CLONES,		0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&wl_clones,	MIN_WL_CLONES,	MAX_WL_CLONES,	DEF_WL_CLONES,	opt_path_metric,
			ARG_VALUE_FORM,	"broadcast OGMs per ogm-interval for wireless devices with\n"
			"	given probability [%] (eg 200% will broadcast the same OGM twice)"},

	{ODI,0,ARG_ASYM_WEIGHT,	        0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&asym_weight,	MIN_ASYM_WEIGHT,MAX_ASYM_WEIGHT,DEF_ASYM_WEIGHT,opt_path_metric,
			ARG_VALUE_FORM,	"ignore OGMs (rcvd via asymmetric links) with given probability [%] to better reflect asymmetric-links"},

        // there SHOULD! be a minimal lateness_penalty >= 1 ! Otherwise a shorter path with equal path-cost than a longer path will never dominate
	{ODI,0,ARG_LATE_PENAL,  	0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_late_penalty,MIN_LATE_PENAL,MAX_LATE_PENAL, DEF_LATE_PENAL, opt_path_metric,
			ARG_VALUE_FORM,	"penalize non-first rcvd OGMs "},

#endif
	{ODI,0,ARG_DAD_TO,        	0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&dad_to,	MIN_DAD_TO,	MAX_DAD_TO,	DEF_DAD_TO,	0,
			ARG_VALUE_FORM,	"duplicate address (DAD) detection timout in seconds"},

	{ODI,0,ARG_TTL,			't',5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_ttl,	MIN_TTL,	MAX_TTL,	DEF_TTL,	opt_path_metric,
			ARG_VALUE_FORM,	"set time-to-live (TTL) for OGMs of primary interface"},

	{ODI,0,ARG_PURGE_TO,    	0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&purge_to,	MIN_PURGE_TO,	MAX_PURGE_TO,	DEF_PURGE_TO,	0,
			ARG_VALUE_FORM,	"timeout in seconds for purging stale originators"}
,

	{ODI,0,"flush_all",		0,  5,A_PS0,A_ADM,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0, 		opt_purge,
			0,		"purge all neighbors and routes on the fly"},

	{ODI,0,ARG_OGI_PWRSAVE, 	0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&ogi_pwrsave,   MIN_OGM_INTERVAL,	MAX_OGM_INTERVAL,	MIN_OGM_INTERVAL,      	0,
			ARG_VALUE_FORM,	"enable power-saving feature by setting increased OGI when no other nodes are in range"}


};

IDM_T validate_name( char* name ) {

        int i,len;
        if ( (len = strlen( name )) >= DESCRIPTION0_ID_NAME_LEN )
                return FAILURE;

        for (i = 0; i < len; i++) {

                char c = name[i];

                if (c == '"' || c < ' ' || c > '~')
                        return FAILURE;

        }

        return SUCCESS;
}

STATIC_FUNC
void init_bmx(void)
{

        static uint8_t my_desc0[MAX_PKT_MSG_SIZE];

        memset( &my_orig_node, 0, sizeof(struct orig_node));

        AVL_INIT_TREE((my_orig_node.router_tree), struct router_node, key);

        my_orig_node.desc0 = (struct description *) my_desc0;

        if (gethostname(my_orig_node.id.name, DESCRIPTION0_ID_NAME_LEN))
                cleanup_all(-500240);

        my_orig_node.id.name[DESCRIPTION0_ID_NAME_LEN - 1] = 0;

        if (validate_name(my_orig_node.id.name) == FAILURE) {
                dbg(DBGL_SYS, DBGT_ERR, "illegal hostname %s", my_orig_node.id.name);
                cleanup_all(-500272);
        }

        my_orig_node.id.rand.u16[0] = (uint16_t) rand_num(U16_MAX);
        my_orig_node.id.rand.u16[1] = (uint16_t) rand_num(U16_MAX);
        my_orig_node.id.rand.u16[2] = (uint16_t) rand_num(U16_MAX);
        my_orig_node.id.rand.u16[3] = (uint16_t) rand_num(U16_MAX);

        my_orig_node.ogm_sqn_min = (((uint16_t) rand_num(MAX_SQN)) & (MAX_SQN << MAX_OGM0_PQ_BITS));

        my_orig_node.desc0_sqn = rand_num(MAX_SQN);

        avl_insert( &orig_tree, &my_orig_node, -300175 );

	register_options_array( bmx_options, sizeof( bmx_options ) );

}




STATIC_FUNC
void bmx(void)
{

	struct list_node *list_pos;
	struct dev_node *dev;
	uint32_t regular_timeout, statistic_timeout;

	uint32_t s_last_cpu_time = 0, s_curr_cpu_time = 0;

	regular_timeout = statistic_timeout = bmx_time;

	on_the_fly = YES;

	while ( !terminating() ) {

		uint32_t wait = whats_next( );

		if ( wait )
			wait4Event( MIN( wait, MAX_SELECT_TIMEOUT_MS ) );

		// The regular tasks...
		if ( LESS_U32( regular_timeout + 1000,  bmx_time ) ) {


                        // check for changed kernel konfigurations...
			check_kernel_config( NULL );

			// check for changed interface konfigurations...
                        struct avl_node *an = NULL;
                        while ((dev = avl_iterate_item(&dev_name_tree, &an))) {

				if ( dev->active )
					check_kernel_config( dev );

                                purge_tx_timestamp_tree(dev, NO);

                        }

                        purge_orig(NULL, YES);

                        purge_dhash_to_list(NO);

			close_ctrl_node( CTRL_CLEANUP, 0 );

			list_for_each( list_pos, &dbgl_clients[DBGL_ALL] ) {

				struct ctrl_node *cn = (list_entry( list_pos, struct dbgl_node, list ))->cn;

				dbg_printf( cn, "------------------ DEBUG ------------------ \n" );

				check_apply_parent_option( ADD, OPT_APPLY, 0, get_option( 0, 0, ARG_STATUS ), 0, cn );
				check_apply_parent_option( ADD, OPT_APPLY, 0, get_option( 0, 0, ARG_LINKS ), 0, cn );
                                check_apply_parent_option( ADD, OPT_APPLY, 0, get_option( 0, 0, ARG_ORIGINATORS ), 0, cn );
				dbg_printf( cn, "--------------- END DEBUG ---------------\n" );

			}

			/* preparing the next debug_timeout */
			regular_timeout = bmx_time;
		}


		if ( LESS_U32( statistic_timeout + 5000, bmx_time ) ) {

                        struct orig_node *on;
                        struct description_id id;

                        memset(&id, 0, sizeof (struct description_id));

                        while ((on = avl_next_item(&blocked_tree, &id))) {

                                memcpy( &id, &on->id, sizeof(struct description_id));

                                dbgf_all( DBGT_INFO, "trying to unblock %s...", on->desc0->id.name);

                                IDM_T tlvs_res = process_description_tlvs(on, on->desc0, TLV_DEL_TEST_ADD, NULL);

                                assertion(-500364, (tlvs_res == TLVS_BLOCKED || tlvs_res == TLVS_SUCCESS));

                                dbgf(DBGL_CHANGES, DBGT_INFO, "unblocking %s %s !",
                                        on->desc0->id.name, tlvs_res == TLVS_SUCCESS ? "success" : "failed");

                        }


			// check for corrupted memory..
			checkIntegrity();


			/* generating cpu load statistics... */
			s_curr_cpu_time = (uint32_t)clock();

			s_curr_avg_cpu_load = ( (s_curr_cpu_time - s_last_cpu_time) / (uint32_t)(bmx_time - statistic_timeout) );

			s_last_cpu_time = s_curr_cpu_time;

			statistic_timeout = bmx_time;
		}
	}

}

int main( int argc, char *argv[] )
{


        // make sure we are using compatible description0 sizes:
        assertion(-500201, (MSG_DESCRIPTION0_ADV_SIZE == sizeof ( struct msg_description_adv)));

	gettimeofday( &start_time_tv, NULL );
	gettimeofday( &new_tv, NULL );

	upd_time( NULL );

	My_pid = getpid();

	srand( My_pid );

	init_set_bits_table256();


	signal( SIGINT, handler );
	signal( SIGTERM, handler );
	signal( SIGPIPE, SIG_IGN );
	signal( SIGSEGV, segmentation_fault );

	init_control();

	init_route();

	init_bmx();

        init_msg();

	init_schedule();

        init_avl();

	init_plugin();

	apply_init_args( argc, argv );

	check_kernel_config( NULL );

        bmx();

	cleanup_all( CLEANUP_SUCCESS );

	return -1;
}



