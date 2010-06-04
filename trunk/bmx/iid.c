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

#include "bmx.h"
#include "iid.h"

struct iid_repos my_iid_repos = { 0,0,0,0,{NULL} };

int8_t iid_extend_repos(struct iid_repos *rep)
{
        dbgf_all(DBGT_INFO, "sizeof iid: %lu,  tot_used %d  arr_size %d ",
                (rep == &my_iid_repos) ? sizeof (IID_NODE_T*) : sizeof (IID_T), rep->tot_used, rep->arr_size);

        paranoia(-500217, (rep == &my_iid_repos && rep->tot_used != rep->arr_size));

        if (rep->arr_size + IID_REPOS_SIZE_BLOCK >= IID_REPOS_SIZE_WARN) {

                dbgf( DBGL_SYS, DBGT_WARN, "%d", rep->arr_size);

                if (rep->arr_size + IID_REPOS_SIZE_BLOCK >= IID_REPOS_SIZE_MAX)
                        return FAILURE;
        }

        int field_size = (rep == &my_iid_repos) ? sizeof (IID_NODE_T*) : sizeof (struct iid_ref);

        if (rep->arr_size) {

                rep->arr.u8 = debugRealloc(rep->arr.u8, (rep->arr_size + IID_REPOS_SIZE_BLOCK) * field_size, -300035);

        } else {

                rep->arr.u8 = debugMalloc(IID_REPOS_SIZE_BLOCK * field_size, -300085);
                rep->tot_used = IID_RSVD_MAX+1;
                rep->min_free = IID_RSVD_MAX+1;
                rep->max_free = IID_RSVD_MAX+1;
        }

        memset(&(rep->arr.u8[rep->arr_size * field_size]), 0, IID_REPOS_SIZE_BLOCK * field_size);

        rep->arr_size += IID_REPOS_SIZE_BLOCK;

        return SUCCESS;
}


void iid_purge_repos( struct iid_repos *rep )
{

        if (rep->arr.u8)
                debugFree(rep->arr.u8, -300135);

        memset(rep, 0, sizeof ( struct iid_repos));

}

void iid_free(struct iid_repos *rep, IID_T iid)
{
        int m = (rep == &my_iid_repos);

        assertion(-500330, (iid > IID_RSVD_MAX));
        assertion(-500228, (iid < rep->arr_size && iid < rep->max_free && rep->tot_used > IID_RSVD_MAX));
        assertion(-500229, ((m ? (rep->arr.node[iid] != NULL) : (rep->arr.ref[iid].myIID4x) != 0)));

        if (m) {
                rep->arr.node[iid] = NULL;
        } else {
                rep->arr.ref[iid].myIID4x = 0;
                rep->arr.ref[iid].referred_timestamp_sec = 0;
        }

        rep->min_free = MIN(rep->min_free, iid);

        if (rep->max_free == iid + 1) {

                IID_T i;

                for (i = iid; i > IID_MIN_USED; i--) {

                        if (m ? (rep->arr.node[i - 1] != NULL) : (rep->arr.ref[i - 1].myIID4x) != 0)
                                break;
                }

                rep->max_free = i;
        }

        rep->tot_used--;

        dbgf_all( DBGT_INFO, "mine %d, iid %d tot_used %d, min_free %d max_free %d",
                m, iid, rep->tot_used, rep->min_free, rep->max_free);

        if (rep->tot_used > 0 && rep->tot_used <= IID_MIN_USED) {

                assertion(-500362, (rep->tot_used == IID_MIN_USED && rep->max_free == IID_MIN_USED && rep->min_free == IID_MIN_USED));

                iid_purge_repos( rep );

        }

}



IID_NODE_T* iid_get_node_by_myIID4x( IID_T myIID4x ) {

        if ( my_iid_repos.max_free <= myIID4x )
                return NULL;

        IID_NODE_T *dhn = my_iid_repos.arr.node[myIID4x];

        assertion(-500328, (!dhn || dhn->myIID4orig == myIID4x));

        if (dhn) {

                if (!dhn->on) {
                        dbgf_all( DBGT_INFO, "myIID4x %d INVALIDATED %d sec ago",
                                myIID4x, (bmx_time - dhn->referred_timestamp) / 1000);
                }

                dhn->referred_timestamp = bmx_time;
        }


        return dhn;
}


IID_NODE_T* iid_get_node_by_neighIID4x( IID_NEIGH_T *nn, IID_T neighIID4x )
{

        if (!nn || nn->neighIID4x_repos.max_free <= neighIID4x)
                return NULL;

        struct iid_ref *ref = &(nn->neighIID4x_repos.arr.ref[neighIID4x]);


        if (ref->myIID4x && ((((uint16_t) bmx_time_sec) - ref->referred_timestamp_sec) <=
                ((MIN_DHASH_TO - (MIN_DHASH_TO / DHASH_TO_TOLERANCE_FK)) / 1000))) {

                ref->referred_timestamp_sec = bmx_time_sec;

                return iid_get_node_by_myIID4x(ref->myIID4x);
        }

        return NULL;
}



int8_t iid_set_neighIID4x(struct iid_repos *neigh_rep, IID_T neighIID4x, IID_T myIID4x)
{
        assertion(-500326, (neighIID4x > IID_RSVD_MAX));
        assertion(-500327, (myIID4x > IID_RSVD_MAX));
        assertion(-500384, (neigh_rep && neigh_rep != &my_iid_repos));

        assertion(-500245, (my_iid_repos.max_free > myIID4x));

        IID_NODE_T *dhn = my_iid_repos.arr.node[myIID4x];

        assertion(-500485, (dhn && dhn->on));

        dhn->referred_timestamp = bmx_time;

        if (neigh_rep->max_free > neighIID4x) {

                struct iid_ref *ref = &(neigh_rep->arr.ref[neighIID4x]);

                if (ref->myIID4x > IID_RSVD_MAX) {

                        if (ref->myIID4x == myIID4x ||
                                (((uint16_t)(((uint16_t) bmx_time_sec) - ref->referred_timestamp_sec)) >=
                                ((MIN_DHASH_TO - (MIN_DHASH_TO / DHASH_TO_TOLERANCE_FK)) / 1000))) {

                                neigh_rep->arr.ref[neighIID4x].myIID4x = myIID4x;
                                neigh_rep->arr.ref[neighIID4x].referred_timestamp_sec = bmx_time_sec;
                                return SUCCESS;
                        }

                        dbgf(DBGL_SYS, DBGT_ERR, "neighIID4x %d for %s changed (at sec %d ) faster than allowed!!",
                                neighIID4x, dhn->on->id.name, ref->referred_timestamp_sec);
                        
                        return FAILURE;
                }

                assertion(-500242, (ref->myIID4x == IID_RSVD_UNUSED));
        }


        while (neigh_rep->arr_size <= neighIID4x) {

                if (neigh_rep->tot_used < neigh_rep->arr_size / IID_REPOS_USAGE_WARNING) {
                        dbgf(DBGL_SYS, DBGT_WARN, "IID_REPOS_USAGE_WARNING did %d sid %d arr_size %d used %d",
                                neighIID4x, myIID4x, neigh_rep->arr_size, neigh_rep->tot_used );
                }

                iid_extend_repos(neigh_rep);
        }

        assertion(-500243, ((neigh_rep->arr_size > neighIID4x &&
                (neigh_rep->max_free <= neighIID4x || neigh_rep->arr.ref[neighIID4x].myIID4x == IID_RSVD_UNUSED))));

        neigh_rep->tot_used++;
        neigh_rep->max_free = MAX( neigh_rep->max_free, neighIID4x+1 );

        IID_T min = neigh_rep->min_free;

        if (min == neighIID4x) {
                for (; min < neigh_rep->arr_size && neigh_rep->arr.ref[min].myIID4x; min++);
        }

        paranoia(-500244, (min > neigh_rep->max_free));

        neigh_rep->min_free = min;

        neigh_rep->arr.ref[neighIID4x].myIID4x = myIID4x;
        neigh_rep->arr.ref[neighIID4x].referred_timestamp_sec = bmx_time_sec;

        return SUCCESS;
}

void iid_free_neighIID4x_by_myIID4x( struct iid_repos *rep, IID_T myIID4x)
{
        assertion(-500282, (rep != &my_iid_repos));
        assertion(-500328, (myIID4x > IID_RSVD_MAX));

        IID_T p;

        for (p = IID_RSVD_MAX + 1; p < rep->max_free && rep->arr.ref[p].myIID4x != myIID4x; p++);

        if (p < rep->max_free && rep->arr.ref[p].myIID4x == myIID4x) {

                dbgf_all(DBGT_INFO, "removed stale rep->arr.sid[%d] = %d", p, myIID4x);

                iid_free(rep, p);
        }
}

IID_T iid_new_myIID4x(IID_NODE_T *dhn)
{

        paranoia( -500216, ( my_iid_repos.tot_used > my_iid_repos.arr_size ) );

        while ( my_iid_repos.tot_used >= my_iid_repos.arr_size )
                iid_extend_repos( &my_iid_repos );

        IID_T mid = my_iid_repos.min_free;
        IID_T pos = mid + 1;


        my_iid_repos.tot_used++;
        my_iid_repos.arr.node[mid] = dhn;

        for (; pos < my_iid_repos.arr_size && (my_iid_repos.arr.node[pos]); pos++);

        my_iid_repos.min_free = pos;
        my_iid_repos.max_free = MAX(pos, my_iid_repos.max_free);

        dbgf_all(DBGT_INFO, "mine %d, iid %d tot_used %d, min_free %d max_free %d",
                1, mid, my_iid_repos.tot_used, my_iid_repos.min_free, my_iid_repos.max_free);

        dhn->referred_timestamp = bmx_time;

        return mid;
}

