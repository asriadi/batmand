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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>     /* ifr_if, ifr_tun */
#include <linux/rtnetlink.h>


#include "bmx.h"
#include "msg.h"
#include "plugin.h"
#include "route.h"
#include "schedule.h"

#define OUT_SEQNO_OFFSET 1



#ifndef NO_PARANOIA
#define DEF_SIM_PARA NO
static int32_t sim_paranoia = DEF_SIM_PARA;
#endif


static LIST_SIMPEL( task_list, struct task_node, list );

static int32_t receive_max_sock = 0;
static fd_set receive_wait_set;

static uint16_t changed_readfds = 1;

static int ifevent_sk = -1;

#ifdef BMX2_TODO
static struct ext_packet my_pip_extension_packet;
#endif

void change_selects( void ) {
	changed_readfds++;	
}


static void check_selects( void ) {
	
	if( changed_readfds == 0 )
		return;
	
	struct list_node *list_pos;
	
	dbgf_all( DBGT_INFO, "%d select fds changed... ", changed_readfds );
	
	changed_readfds = 0;
	
	FD_ZERO(&receive_wait_set);
	receive_max_sock = 0;
	
	receive_max_sock = ifevent_sk;
	FD_SET(ifevent_sk, &receive_wait_set);
	
	if ( receive_max_sock < unix_sock )
		receive_max_sock = unix_sock;
	
	FD_SET(unix_sock,  &receive_wait_set);
	
	list_for_each( list_pos, &ctrl_list ) {
		
		struct ctrl_node *cn = list_entry( list_pos, struct ctrl_node, list );
		
		if ( cn->fd > 0  &&  cn->fd != STDOUT_FILENO ) {
			
			receive_max_sock = MAX( receive_max_sock, cn->fd);
			
			FD_SET( cn->fd, &receive_wait_set );
		}
	}
	
        struct avl_node *it=NULL;
        struct dev_node *bif;
        while ((bif = avl_iterate_item(&dev_ip4_tree, &it))) {

		if ( bif->active  &&  bif->linklayer != VAL_DEV_LL_LO ) {
			
			receive_max_sock = MAX( receive_max_sock, bif->unicast_sock );
			
			FD_SET(bif->unicast_sock, &receive_wait_set);
			
			receive_max_sock = MAX( receive_max_sock, bif->netwbrc_sock );
			
			FD_SET(bif->netwbrc_sock, &receive_wait_set);
			
			if (bif->fullbrc_sock > 0) {
				
				receive_max_sock = MAX( receive_max_sock, bif->fullbrc_sock );
				
				FD_SET(bif->fullbrc_sock, &receive_wait_set);
				
			}
		}
	}
	
	list_for_each( list_pos, &cb_fd_list ) {
		
		struct cb_fd_node *cdn = list_entry( list_pos, struct cb_fd_node, list );
		
		receive_max_sock = MAX( receive_max_sock, cdn->fd );
		
		FD_SET( cdn->fd, &receive_wait_set );
		
	}
	
}





void register_task( uint32_t timeout, void (* task) (void *), void *data )
{

        assertion(-500475, (remove_task(task, data) == FAILURE));

	struct list_node *list_pos, *prev_pos = (struct list_node *)&task_list;
	struct task_node *tmp_tn = NULL;

	
	//TODO: allocating and freeing tn and tn->data may be much faster when done by registerig function.. 
	struct task_node *tn = debugMalloc( sizeof( struct task_node ), -300034 );
	memset( tn, 0, sizeof(struct task_node) );
	
	tn->expire = bmx_time + timeout;
	tn->task = task;
	tn->data = data;
	
	
	list_for_each( list_pos, &task_list ) {

		tmp_tn = list_entry( list_pos, struct task_node, list );

		if ( GREAT_U32(tmp_tn->expire, tn->expire) ) {

                        list_add_after(&task_list, prev_pos, &tn->list);
			break;

		}

		prev_pos = &tmp_tn->list;

	}

	if ( ( tmp_tn == NULL ) || ( LSEQ_U32(tmp_tn->expire, tn->expire) ))
                list_add_tail(&task_list, &tn->list);
	
}

IDM_T remove_task( void (* task) (void *), void *data ) {
	
	struct list_node *list_pos, *tmp_pos, *prev_pos = (struct list_node*)&task_list;
        IDM_T ret = FAILURE;
		
	list_for_each_safe( list_pos, tmp_pos, &task_list ) {
			
		struct task_node *tn = list_entry( list_pos, struct task_node, list );
			
		if ( tn->task == task && tn->data == data  ) {

                        list_del_next(&task_list, prev_pos);
			
			debugFree( tn, -300080 );
#ifdef NO_PARANOIA
                        return SUCCESS;
#else
                        assertion(-500474, (ret == FAILURE));
                        ret = SUCCESS;
#endif
			
		} else {
			
			prev_pos = list_pos;
		}
	}

        return ret;
}


uint32_t whats_next( void ) {
	
	struct list_node *list_pos, *tmp_pos, *prev_pos = (struct list_node*)&task_list;

        paranoia( -500175, sim_paranoia );

	list_for_each_safe( list_pos, tmp_pos, &task_list ) {
			
		struct task_node *tn = list_entry( list_pos, struct task_node, list );
			
		if ( LSEQ_U32( tn->expire, bmx_time )  ) {


			list_del_next( &task_list, prev_pos );
			
			(*(tn->task)) (tn->data);
			
			debugFree( tn, -300081 );

                        CHECK_INTEGRITY();

                        return 0;
			
		} else {
			
			return tn->expire - bmx_time;
		}
	}
	
	return MAX_SELECT_TIMEOUT_MS;
}


static int open_ifevent_netlink_sk( void ) {
	
	struct sockaddr_nl sa;
	int32_t unix_opts;	
	memset (&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups |= RTMGRP_IPV4_IFADDR;
	sa.nl_groups |= RTMGRP_LINK; // (this can result in select storms with buggy wlan devices
	
	if ( ( ifevent_sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) ) < 0 ) {
		dbg( DBGL_SYS, DBGT_ERR, "can't create af_netlink socket for reacting on if up/down events: %s",
		     strerror(errno) );
		ifevent_sk = 0;
		return -1;
	}
	
	
	unix_opts = fcntl( ifevent_sk, F_GETFL, 0 );
	fcntl( ifevent_sk, F_SETFL, unix_opts | O_NONBLOCK );
	
	if ( ( bind( ifevent_sk, (struct sockaddr*)&sa, sizeof(sa) ) ) < 0 ) {
		dbg( DBGL_SYS, DBGT_ERR, "can't bind af_netlink socket for reacting on if up/down events: %s",
		     strerror(errno) );
		ifevent_sk = 0;
		return -1;
	}
	
	change_selects();
	
	return ifevent_sk;
}

static void close_ifevent_netlink_sk( void ) {
	
	if ( ifevent_sk > 0 )
		close( ifevent_sk );
	
	ifevent_sk = 0;
}

static void recv_ifevent_netlink_sk( void ) {
	char buf[4096]; //test this with a very small value !!

	struct sockaddr_nl sa;

        struct iovec iov;

        memset(&iov, 0, sizeof (struct iovec));

        iov.iov_base = buf;
        iov.iov_len = sizeof (buf);

        struct msghdr msg; // = {(void *) & sa, sizeof (sa), &iov, 1, NULL, 0, 0};
        memset( &msg, 0, sizeof( struct msghdr));
        msg.msg_name = (void *)&sa;
        msg.msg_namelen = sizeof(sa); /* Length of address data.  */
        msg.msg_iov = &iov; /* Vector of data to send/receive into.  */
        msg.msg_iovlen = 1; /* Number of elements in the vector.  */

	while( recvmsg (ifevent_sk, &msg, 0) > 0 );
	
	//so fare I just want to consume the pending message...	
}









void wait4Event( uint32_t timeout ) {
	
	static struct packet_buff pb;
	
	uint32_t last_get_time_result = 0;
	
	static uint32_t addr_len = sizeof(struct sockaddr_in);

	uint32_t return_time = bmx_time + timeout;
	struct timeval tv;
	struct list_node *list_pos;
	int selected;
	fd_set tmp_wait_set;
		
	
loop4Event:
	
	while ( GREAT_U32(return_time, bmx_time) ) {
		
		check_selects();
		
		memcpy( &tmp_wait_set, &receive_wait_set, sizeof(fd_set) );
			
		tv.tv_sec  =   (return_time - bmx_time) / 1000;
		tv.tv_usec = ( (return_time - bmx_time) % 1000 ) * 1000;
			
		selected = select( receive_max_sock + 1, &tmp_wait_set, NULL, NULL, &tv );
	
		upd_time( &(pb.tv_stamp) );
		
		//omit debugging here since event could be a closed -d4 ctrl socket 
		//which should be removed before debugging
		//dbgf_all( DBGT_INFO, "timeout %d", timeout );
		
		if ( bmx_time < last_get_time_result ) {
				
			last_get_time_result = bmx_time;
			dbg( DBGL_SYS, DBGT_WARN, "detected Timeoverlap..." );
			
			goto wait4Event_end;
		}
	
		last_get_time_result = bmx_time;
					
		if ( selected < 0 ) {
			
			dbg( DBGL_SYS, DBGT_WARN, //happens when receiving SIGHUP 
			     "can't select! Waiting a moment! errno: %s", strerror(errno) );
			
			wait_sec_msec( 0, 1 );
			upd_time( NULL );
			
			goto wait4Event_end;
		
		}
	
		if ( selected == 0 ) {
	
			//Often select returns just a few milliseconds before being scheduled
			if ( LESS_U32( return_time, (bmx_time + 10) ) ) {
					
				//cheating time :-)
				bmx_time = return_time;
				
				goto wait4Event_end;
			}
					
			//if ( LESS_U32( return_time, bmx_time ) )
			dbg_mute( 50, DBGL_CHANGES, DBGT_WARN, 
			     "select() returned %d without reason!! return_time %d, curr_time %d", 
			     selected, return_time, bmx_time );
				
			goto loop4Event;
		}
		
		// check for changed interface status...
		if ( FD_ISSET( ifevent_sk, &tmp_wait_set ) ) {
			
			dbg_mute( 40, DBGL_CHANGES, DBGT_INFO,
			     "select() indicated changed interface status! Going to check interfaces!" );
			
			recv_ifevent_netlink_sk( );
			
			//do NOT delay checking of interfaces to not miss ifdown/up of interfaces !!
			dev_check();
			
			goto wait4Event_end;
		}
		
		
		// check for received packets...
                struct avl_node *it = NULL;
                while ((pb.iif = avl_iterate_item(&dev_ip4_tree, &it))) {

			if ( pb.iif->linklayer == VAL_DEV_LL_LO )
				continue;
				
			if ( FD_ISSET( pb.iif->netwbrc_sock, &tmp_wait_set ) ) {
	
				pb.unicast = NO;
				
				errno=0;
				pb.total_length = recvfrom( pb.iif->netwbrc_sock, pb.packet_in,
				                             sizeof(pb.packet_in) - 1, 0,
				                             (struct sockaddr *)&pb.addr, &addr_len );
				
				if ( pb.total_length < 0  &&  ( errno == EWOULDBLOCK || errno == EAGAIN ) ) {
					
					dbgf(DBGL_SYS, DBGT_WARN, 
					    "sock returned %d errno %d: %s",
					    pb.total_length, errno, strerror(errno) );
					
					continue;
				}

				ioctl(pb.iif->netwbrc_sock, SIOCGSTAMP, &(pb.tv_stamp)) ;
				
				rx_packet( &pb );
				
				if ( --selected == 0 )
					goto loop4Event;

			}
			
			if ( FD_ISSET( pb.iif->fullbrc_sock, &tmp_wait_set ) ) {
				
				pb.unicast = NO;
				
				errno=0;
				pb.total_length = recvfrom( pb.iif->fullbrc_sock, pb.packet_in,
				                             sizeof(pb.packet_in) - 1, 0,
				                             (struct sockaddr *)&pb.addr, &addr_len );
				
				if ( pb.total_length < 0  &&  ( errno == EWOULDBLOCK || errno == EAGAIN ) ) {
					
					dbgf(DBGL_SYS, DBGT_WARN, 
					     "sock returned %d errno %d: %s",
					     pb.total_length, errno, strerror(errno) );
					
					continue;
				}
				
				ioctl(pb.iif->fullbrc_sock, SIOCGSTAMP, &(pb.tv_stamp)) ;
				
				rx_packet( &pb );
				
				if ( --selected == 0 )
					goto loop4Event;
				
			}
			
			
			if ( FD_ISSET( pb.iif->unicast_sock, &tmp_wait_set ) ) {
				
				pb.unicast = YES;
					
				struct msghdr msghdr;
				struct iovec iovec;
				char buf[4096];
				struct cmsghdr *cp;
				struct timeval *tv_stamp = NULL;
	
				iovec.iov_base = pb.packet_in;
				iovec.iov_len = sizeof(pb.packet_in) - 1;
				
				msghdr.msg_name = (struct sockaddr *)&pb.addr;
				msghdr.msg_namelen = addr_len;
				msghdr.msg_iov = &iovec;
				msghdr.msg_iovlen = 1;
				msghdr.msg_control = buf;
				msghdr.msg_controllen = sizeof( buf );
				msghdr.msg_flags = 0;
				
				errno=0;
				
				pb.total_length = recvmsg( pb.iif->unicast_sock, &msghdr, MSG_DONTWAIT  );
				
				if ( pb.total_length < 0  &&  ( errno == EWOULDBLOCK || errno == EAGAIN ) ) {
					dbgf(DBGL_SYS, DBGT_WARN, 
					    "sock returned %d errno %d: %s",
					    pb.total_length, errno, strerror(errno) );
					continue;
				}
						
#ifdef SO_TIMESTAMP
				for (cp = CMSG_FIRSTHDR(&msghdr); cp; cp = CMSG_NXTHDR(&msghdr, cp)) {
						
					if ( 	cp->cmsg_type == SO_TIMESTAMP && 
						cp->cmsg_level == SOL_SOCKET && 
						cp->cmsg_len >= CMSG_LEN(sizeof(struct timeval)) )  {
	
						tv_stamp = (struct timeval*)CMSG_DATA(cp);
						break;
					}
				}
#endif
				if ( tv_stamp == NULL )
					ioctl( pb.iif->unicast_sock, SIOCGSTAMP, &(pb.tv_stamp) );
				else
					timercpy( tv_stamp, &(pb.tv_stamp) );
				
				rx_packet( &pb );
				
				if ( --selected == 0)
					goto loop4Event;
					//goto wait4Event_end;

			}
		
		}
		
loop4ActivePlugins:

		// check active plugins...
		list_for_each( list_pos, &cb_fd_list ) {
	
			struct cb_fd_node *cdn = list_entry( list_pos, struct cb_fd_node, list );
	
			if ( FD_ISSET( cdn->fd, &tmp_wait_set ) ) {
				
				FD_CLR( cdn->fd, &tmp_wait_set );
				
				(*(cdn->cb_fd_handler)) (cdn->fd); 
				
				// list might have changed, due to unregistered handlers, reiterate NOW
				//TBD: check if fd was really consumed !
				if ( --selected == 0 )
					goto loop4Event;
					//goto wait4Event_end;
				
				goto loop4ActivePlugins;
			}

		}
		

		// check for new control clients...
		if ( FD_ISSET( unix_sock, &tmp_wait_set ) ) {
				
			dbgf_all( DBGT_INFO, "new control client..." );
				
			accept_ctrl_node();
			
			if ( --selected == 0 )
				goto loop4Event;
			
			//goto wait4Event_end;
		}
			
	
loop4ActiveClients:
		// check for all connected control clients...
		list_for_each( list_pos, &ctrl_list ) {
			
			struct ctrl_node *client = list_entry( list_pos, struct ctrl_node, list );
				
			if ( FD_ISSET( client->fd, &tmp_wait_set ) ) {
					
				FD_CLR( client->fd, &tmp_wait_set );
				
				//omit debugging here since event could be a closed -d4 ctrl socket 
				//which should be removed before debugging
				//dbgf_all( DBGT_INFO, "got msg from control client");
					
				handle_ctrl_node( client );
				
				--selected;
				
				// return straight because client might be removed and list might have changed.
				goto loop4ActiveClients;
			} 
		
		}

		
	
		if ( selected )
			dbg( DBGL_CHANGES, DBGT_WARN, 
			     "select() returned with  %d unhandled event(s)!! return_time %d, curr_time %d",
			     selected, return_time, bmx_time );
		
		break;
	}
	
wait4Event_end:
	
	dbgf_all( DBGT_INFO, "end of function");
	
	return;
}





static struct opt_type schedule_options[]= 
{
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	
	{ODI,0,0,			0,  5,0,0,0,0,0,				0,		0,		0,		0,		0,
			0,		"\nScheduling options:"}

#ifndef LESS_OPTIONS
#ifndef NO_PARANOIA
	,{ODI,0,"simulate_cleanup",	0,  5,A_PS1,A_ADM,A_DYI,A_ARG,A_ANY,	&sim_paranoia,   NO,	        YES,	        DEF_SIM_PARA,  	0,
			ARG_VALUE_FORM,	"simulate paranoia and cleanup_all for testing"}
#endif
#endif

};



void init_schedule( void ) {

#ifdef BMX2_TODO
        memset( &my_pip_extension_packet, 0, sizeof(struct ext_packet) );
	my_pip_extension_packet.EXT_FIELD_MSG = YES;
	my_pip_extension_packet.EXT_FIELD_TYPE = EXT_TYPE_64B_PIP;
#endif
	if ( open_ifevent_netlink_sk() < 0 )
		cleanup_all( -500150 );
	
	register_options_array( schedule_options, sizeof( schedule_options ) );
}



void cleanup_schedule( void ) {
	

        struct task_node *tn;

        while ( (tn = list_rem_head( &task_list )))
                debugFree(tn, -300082);

/*
                struct list_node *list_pos_tmp, *list_pos;
	list_for_each_safe( list_pos, list_pos_tmp, &task_list ) {
		
		struct task_node *tn = list_entry( list_pos, struct task_node, list );
		
		list_del_next( &task_list, (struct list_node *)&task_list );

                debugFree(tn, -300082);
	}
*/
        
	close_ifevent_netlink_sk();	
}
