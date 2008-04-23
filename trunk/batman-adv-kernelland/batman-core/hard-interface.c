/*
 * Copyright (C) 2007-2008 B.A.T.M.A.N. contributors:
 * Marek Lindner
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
 *
 */





#include "batman-adv-main.h"
#include "hard-interface.h"
#include "batman-adv-log.h"
#include "batman-adv-interface.h"
#include "batman-adv-send.h"
#include "batman-adv-ttable.h"
#include "batman-adv-routing.h"



static DECLARE_WORK(hardif_check_interfaces_wq, hardif_check_interfaces_status);

static char avail_ifs = 0;
static char active_ifs = 0;

static struct timer_list hardif_check_timer;



/* checks if the interface is up. (returns 1 if it is) */
int hardif_is_interface_up(char *dev)
{
	struct net_device *net_dev;

	/**
	 * if we already have an interface in our interface list and
	 * the current interface is not the primary interface and
	 * the primary interface is not up and
	 * the primary interface has never been up - don't activate any secondary interface !
	 */

	if ((!list_empty(&if_list)) &&
		     (strncmp(((struct batman_if *)if_list.next)->dev, dev, IFNAMSIZ) != 0) &&
		     !(((struct batman_if *)if_list.next)->if_active == IF_ACTIVE) &&
		     (!main_if_was_up())) {

		goto end;

	}

#ifdef __NET_NET_NAMESPACE_H
	if ((net_dev = dev_get_by_name(&init_net, dev)) == NULL)
#else
	if ((net_dev = dev_get_by_name(dev)) == NULL)
#endif
		goto end;

	if (!(net_dev->flags & IFF_UP))
		goto failure;

	dev_put(net_dev);
	return 1;

failure:
	dev_put(net_dev);
end:
	return 0;
}

/* deactivates the interface. */
void hardif_deactivate_interface(struct batman_if *batman_if)
{
	if (batman_if->raw_sock != NULL)
		sock_release(batman_if->raw_sock);

	/* batman_if->raw_sock->sk->sk_data_ready = batman_if->raw_sock->sk->sk_user_data; */

	/**
	 * batman_if->net_dev has been acquired by dev_get_by_name() in
	 * proc_interfaces_write() and has to be unreferenced.
	 */

	if (batman_if->net_dev != NULL)
		dev_put(batman_if->net_dev);

	batman_if->raw_sock = NULL;
	batman_if->net_dev = NULL;

	batman_if->if_active = IF_INACTIVE;
	active_ifs--;

	debug_log(LOG_TYPE_NOTICE, "Interface deactivated: %s\n", batman_if->dev);
}

/* (re)activate given interface. */
void hardif_activate_interface(struct batman_if *batman_if)
{
	struct sockaddr_ll bind_addr;
	int retval;

#ifdef __NET_NET_NAMESPACE_H
	if ((batman_if->net_dev = dev_get_by_name(&init_net, batman_if->dev)) == NULL)
#else
	if ((batman_if->net_dev = dev_get_by_name(batman_if->dev)) == NULL)
#endif
		goto error;

	if ((retval = sock_create_kern(PF_PACKET, SOCK_RAW, htons(ETH_P_BATMAN), &batman_if->raw_sock)) < 0) {
		debug_log(LOG_TYPE_WARN, "Can't create raw socket: %i\n", retval);
		goto error;
	}

	bind_addr.sll_family = AF_PACKET;
	bind_addr.sll_ifindex = batman_if->net_dev->ifindex;
	bind_addr.sll_protocol = 0;	/* is set by the kernel */

	if ((retval = kernel_bind(batman_if->raw_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr))) < 0) {
		debug_log(LOG_TYPE_WARN, "Can't create bind raw socket: %i\n", retval);
		goto error;
	}

	batman_if->raw_sock->sk->sk_user_data = batman_if->raw_sock->sk->sk_data_ready;
	batman_if->raw_sock->sk->sk_data_ready = batman_data_ready;

	addr_to_string(batman_if->addr_str, batman_if->net_dev->dev_addr);

	memcpy(((struct batman_packet *)(batman_if->pack_buff))->orig, batman_if->net_dev->dev_addr, ETH_ALEN);
	memcpy(((struct batman_packet *)(batman_if->pack_buff))->old_orig, batman_if->net_dev->dev_addr, ETH_ALEN);

	batman_if->if_active = IF_ACTIVE;
	active_ifs++;

	/* save the mac address if it is out primary interface */
	if (batman_if->if_num == 0)
		set_main_if_addr(batman_if->net_dev->dev_addr);

	debug_log(LOG_TYPE_NOTICE, "Interface activated: %s\n", batman_if->dev);

	return;

error:
	hardif_deactivate_interface(batman_if);
}

void hardif_free_interface(struct rcu_head *rcu)
{
	struct batman_if *batman_if = container_of(rcu, struct batman_if, rcu);

	debug_log(LOG_TYPE_NOTICE, "Deleting interface: %s\n", batman_if->dev);

	kfree(batman_if->pack_buff);
	kfree(batman_if->dev);
	kfree(batman_if);
}

/**
 *called by
 *  - echo '' > /proc/.../interfaces
 *  - modprobe -r batman-adv-core
 */
/* removes and frees all interfaces */
void hardif_remove_interfaces(void)
{
	struct batman_if *batman_if = NULL;

	avail_ifs = 0;

	/* TODO: spinlock for the write here. */
	list_for_each_entry(batman_if, &if_list, list) {

		list_del_rcu(&batman_if->list);

		del_timer_sync(&batman_if->bcast_timer);

		/* first deactivate interface */
		if (batman_if->if_active != IF_INACTIVE)
			hardif_deactivate_interface(batman_if);

		call_rcu(&batman_if->rcu, hardif_free_interface);
	}
}

/* adds an interface the interface list and activate it, if possible */
int hardif_add_interface(char *dev, int if_num)
{
	struct batman_if *batman_if;
	struct batman_packet *batman_packet;

	batman_if = kmalloc(sizeof(struct batman_if), GFP_KERNEL);

	if (!batman_if) {
		debug_log(LOG_TYPE_WARN, "Can't add interface (%s): out of memory\n", dev);
		return -1;
	}

	batman_if->raw_sock = NULL;
	batman_if->net_dev = NULL;

	if ((if_num == 0) && (num_hna > 0))
		batman_if->pack_buff_len = sizeof(struct batman_packet) + num_hna * ETH_ALEN;
	else
		batman_if->pack_buff_len = sizeof(struct batman_packet);

	batman_if->pack_buff = kmalloc(batman_if->pack_buff_len, GFP_KERNEL);

	if (!batman_if->pack_buff) {
		debug_log(LOG_TYPE_WARN, "Can't add interface packet (%s): out of memory\n", dev);
		goto out;
	}

	batman_if->if_num = if_num;
	batman_if->dev = dev;
	batman_if->if_active = IF_INACTIVE;
	INIT_RCU_HEAD(&batman_if->rcu);

	debug_log(LOG_TYPE_NOTICE, "Adding interface: %s\n", dev);
	avail_ifs++;

	INIT_LIST_HEAD(&batman_if->list);

	batman_packet = (struct batman_packet *)(batman_if->pack_buff);
	batman_packet->packet_type = BAT_PACKET;
	batman_packet->version = COMPAT_VERSION;
	batman_packet->flags = 0x00;
	batman_packet->ttl = (batman_if->if_num > 0 ? 2 : TTL);
	batman_packet->gwflags = 0;
	batman_packet->flags = 0;
	batman_packet->tq = TQ_MAX_VALUE;
	batman_packet->num_hna = 0;

	if (batman_if->pack_buff_len != sizeof(struct batman_packet))
		batman_packet->num_hna = hna_local_fill_buffer(batman_if->pack_buff + sizeof(struct batman_packet), batman_if->pack_buff_len - sizeof(struct batman_packet));

	batman_if->seqno = 1;
	batman_if->seqno_lock = __SPIN_LOCK_UNLOCKED(batman_if->seqno_lock);

	start_bcast_timer(batman_if);

	if (!hardif_is_interface_up(batman_if->dev))
		debug_log(LOG_TYPE_WARN, "Not using interface %s (retrying later): interface not active\n", batman_if->dev);

	list_add_tail_rcu(&batman_if->list, &if_list);
	return 1;

out:
	kfree(batman_if);
	kfree(dev);
	return -1;
}

char hardif_get_active_if_num(void)
{
	return active_ifs;
}

/* checks inactive interfaces and deactivates "to-be-deactivated" interfaces */
void hardif_check_interfaces_status(struct work_struct *work)
{
	struct batman_if *batman_if;

	if (module_state == MODULE_UNLOADING)
		return;

	/* TODO: spinlock for the write here */
	list_for_each_entry_rcu(batman_if, &if_list, list) {
		if ((batman_if->if_active == IF_INACTIVE) && (hardif_is_interface_up(batman_if->dev)))
			hardif_activate_interface(batman_if);

		if (batman_if->if_active == IF_TO_BE_DEACTIVATED)
			hardif_deactivate_interface(batman_if);
	}

	start_hardif_check_timer();
}

void hardif_check_interfaces_status_timer(unsigned long data)
{
	queue_work(bat_event_workqueue, &hardif_check_interfaces_wq);
}

void start_hardif_check_timer(void)
{
	init_timer(&hardif_check_timer);

	hardif_check_timer.expires = jiffies + (1 * HZ); /* one second */
	hardif_check_timer.data = 0;
	hardif_check_timer.function = hardif_check_interfaces_status_timer;

	add_timer(&hardif_check_timer);
}

void destroy_hardif_check_timer(void)
{
	del_timer_sync(&hardif_check_timer);
}

