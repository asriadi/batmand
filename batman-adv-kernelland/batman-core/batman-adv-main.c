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
#include "batman-adv-proc.h"
#include "batman-adv-log.h"
#include "batman-adv-routing.h"
#include "batman-adv-send.h"
#include "batman-adv-interface.h"
#include "batman-adv-device.h"
#include "batman-adv-ttable.h"
#include "batman-adv-vis.h"
#include "types.h"
#include "hash.h"



struct list_head if_list;
struct hashtable_t *orig_hash;

DEFINE_SPINLOCK(if_list_lock);
DEFINE_SPINLOCK(orig_hash_lock);

atomic_t originator_interval;
atomic_t vis_interval;
int16_t num_hna = 0;
int16_t num_ifs = 0;

struct net_device *bat_device = NULL;

static struct task_struct *kthread_task = NULL;
static struct timer_list purge_timer;

unsigned char broadcastAddr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char hna_local_changed = 0;

static char avail_ifs = 0;
static char active_ifs = 0;



int init_module(void)
{
	int retval;

	INIT_LIST_HEAD(&if_list);
	atomic_set(&originator_interval, 1000);
	atomic_set(&vis_interval, 1000);		/* TODO: raise this later, this is only for debugging now. */

	if ((retval = setup_procfs()) < 0)
		return retval;

	orig_hash = hash_new(128, compare_orig, choose_orig);

	if (orig_hash == NULL)
		goto clean_proc;

	if (hna_local_init() < 0)
		goto free_orig_hash;

	if (hna_global_init() < 0)
		goto free_lhna_hash;

	bat_device_init();

	debug_log(LOG_TYPE_CRIT, "B.A.T.M.A.N. Advanced %s%s (compability version %i) loaded \n", SOURCE_VERSION, (strlen(REVISION_VERSION) > 3 ? REVISION_VERSION : ""), COMPAT_VERSION);

	return 0;

free_lhna_hash:
	hna_local_free();

free_orig_hash:
	hash_delete(orig_hash, free_orig_node);

clean_proc:
	cleanup_procfs();
	return -ENOMEM;
}

void cleanup_module(void)
{
	shutdown_module(0);
	remove_interfaces();

	spin_lock(&orig_hash_lock);
	hash_delete(orig_hash, free_orig_node);
	spin_unlock(&orig_hash_lock);

	hna_local_free();
	hna_global_free();
	cleanup_procfs();
}

void start_purge_timer(void)
{
	init_timer(&purge_timer);

	purge_timer.expires = jiffies + (1 * HZ); /* one second */
	purge_timer.data = 0;
	purge_timer.function = purge_orig;

	add_timer(&purge_timer);
}

void activate_module(void)
{
	struct list_head *list_pos;
	struct batman_if *batman_if = NULL;
	int result;

	/* initialize layer 2 interface */
	if (bat_device == NULL) {

		bat_device = alloc_netdev(sizeof(struct bat_priv) , "bat%d", interface_setup);

		if (bat_device == NULL) {
			debug_log(LOG_TYPE_CRIT, "Unable to allocate the batman interface\n");
			return;
		}

		result = register_netdev(bat_device);

		if (result < 0) {
			debug_log(LOG_TYPE_CRIT, "Unable to register the batman interface: %i\n", result);
			free_netdev(bat_device);
			bat_device = NULL;
			return;
		}

		hna_local_add(bat_device->dev_addr);

	}
	spin_lock(&if_list_lock);
	/* (re)activate all timers (if any) */
	list_for_each(list_pos, &if_list) {
		batman_if = list_entry(list_pos, struct batman_if, list);

		start_bcast_timer(batman_if);
	}
	spin_unlock(&if_list_lock);

	/* (re)start kernel thread for packet processing */
	kthread_task = kthread_run(packet_recv_thread, NULL, "batman-adv");

	if (IS_ERR(kthread_task)) {
		debug_log(LOG_TYPE_CRIT, "Unable to start packet receive thread\n");
		kthread_task = NULL;
	}

	start_purge_timer();

	bat_device_setup();

	vis_init();
}

void shutdown_module(char keep_bat_if)
{
	struct list_head *list_pos;
	struct batman_if *batman_if = NULL;

	vis_quit();

	if ((!keep_bat_if) && (bat_device != NULL)) {
		unregister_netdev(bat_device);
		bat_device = NULL;
	}

	/* deactivate kernel thread for packet processing (if running) */
	if (kthread_task) {
		atomic_set(&exit_cond, 1);
		wake_up_interruptible(&thread_wait);
		kthread_stop(kthread_task);

		kthread_task = NULL;
	}

	spin_lock(&if_list_lock);

	/* deactivate all timers first to avoid race conditions */
	list_for_each(list_pos, &if_list) {
		batman_if = list_entry(list_pos, struct batman_if, list);

		if (batman_if->if_active)
			del_timer_sync(&batman_if->bcast_timer);
	}

	spin_unlock(&if_list_lock);

	if (!(list_empty(&if_list)))
		del_timer_sync(&purge_timer);

	bat_device_destroy();
}

int is_interface_up(char *dev)
{
	struct net_device *net_dev;

	/*
	 * if we already have an interface in our interface list and
	 * the current interface is not the primary interface and
	 * the primary interface is not up and
	 * the primary interface has never been up - don't activate any secondary interface !
	 */

	spin_lock(&if_list_lock);

	if ((!list_empty(&if_list)) &&
		(strncmp(((struct batman_if *)if_list.next)->dev, dev, IFNAMSIZ) != 0) &&
		!(((struct batman_if *)if_list.next)->if_active) &&
		(!main_if_was_up())) {

		spin_unlock(&if_list_lock);
		goto end;

	}

	spin_unlock(&if_list_lock);

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

void deactivate_interface(struct batman_if *batman_if)
{
	if (batman_if->raw_sock != NULL)
		sock_release(batman_if->raw_sock);

	/* batman_if->raw_sock->sk->sk_data_ready = batman_if->raw_sock->sk->sk_user_data; */

	/*
	 * batman_if->net_dev has been acquired by dev_get_by_name() in
	 * proc_interfaces_write() and has to be unreferenced.
	 */
	if (batman_if->net_dev != NULL)
		dev_put(batman_if->net_dev);

	batman_if->raw_sock = NULL;
	batman_if->net_dev = NULL;

	batman_if->if_active = 0;
	active_ifs--;

	debug_log(LOG_TYPE_NOTICE, "Interface deactivated: %s\n", batman_if->dev);
	if (batman_if->if_num == 0) {
		debug_log(LOG_TYPE_CRIT, "Main Interface deactivated, shutting down module.\n", batman_if->dev);
		shutdown_module(0);
	}


}

void activate_interface(struct batman_if *batman_if)
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

	batman_if->if_active = 1;
	active_ifs++;

	/* save the mac address if it is out primary interface */
	if (batman_if->if_num == 0)
		set_main_if_addr(batman_if->net_dev->dev_addr);

	debug_log(LOG_TYPE_NOTICE, "Interface activated: %s\n", batman_if->dev);

	return;

error:
	deactivate_interface(batman_if);
}

void remove_interfaces(void)
{
	struct list_head *list_pos, *list_pos_tmp;
	struct batman_if *batman_if = NULL;

	avail_ifs = 0;

	spin_lock(&if_list_lock);

	/* deactivate all interfaces */
	list_for_each_safe(list_pos, list_pos_tmp, &if_list) {
		batman_if = list_entry(list_pos, struct batman_if, list);

		list_del(list_pos);

		if (batman_if->if_active)
			deactivate_interface(batman_if);

		debug_log(LOG_TYPE_NOTICE, "Deleting interface: %s\n", batman_if->dev);

		kfree(batman_if->pack_buff);
		kfree(batman_if->dev);
		kfree(batman_if);
	}

	spin_unlock(&if_list_lock);
}

int add_interface(char *dev, int if_num)
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
	batman_if->if_active = 0;

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

	if (is_interface_up(batman_if->dev))
		activate_interface(batman_if);
	else
		debug_log(LOG_TYPE_WARN, "Not using interface %s (retrying later): interface not active\n", dev);

	spin_lock(&if_list_lock);
	list_add_tail(&batman_if->list, &if_list);
	spin_unlock(&if_list_lock);

	return 1;

out:
	kfree(batman_if);
	return -1;
}

void check_inactive_interfaces(void)
{
	struct list_head *list_pos;
	struct batman_if *batman_if;

	if (avail_ifs == active_ifs)
		return;

	list_for_each(list_pos, &if_list) {
		batman_if = list_entry(list_pos, struct batman_if, list);

		if ((!batman_if->if_active) && (is_interface_up(batman_if->dev)))
			activate_interface(batman_if);
	}
}

char get_active_if_num(void)
{
	return active_ifs;
}

void inc_module_count(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_INC_USE_COUNT;
#else
	try_module_get(THIS_MODULE);
#endif
}

void dec_module_count(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_DEC_USE_COUNT;
#else
	module_put(THIS_MODULE);
#endif
}

int addr_to_string(char *buff, uint8_t *addr)
{
	return sprintf(buff, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

int compare_orig(void *data1, void *data2)
{
	return (memcmp(data1, data2, ETH_ALEN) == 0 ? 1 : 0);
}

/* hashfunction to choose an entry in a hash table of given size */
/* hash algorithm from http://en.wikipedia.org/wiki/Hash_table */
int choose_orig(void *data, int32_t size)
{
	unsigned char *key= data;
	uint32_t hash = 0;
	size_t i;

	for (i = 0; i < 6; i++) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return (hash%size);
}

int is_my_mac(uint8_t *addr)
{
	struct list_head *list_pos;
	struct batman_if *batman_if;
	int retval = 0;

	spin_lock(&if_list_lock);

	list_for_each(list_pos, &if_list) {
		batman_if = list_entry(list_pos, struct batman_if, list);

		if (compare_orig(batman_if->net_dev->dev_addr, addr)) {
			retval = 1;
			goto end;
		}
	}

end:
	spin_unlock(&if_list_lock);
	return retval;
}

int is_bcast(uint8_t *addr)
{
	return ((addr[0] == (uint8_t)0xff) && (addr[1] == (uint8_t)0xff));
}

int is_mcast(uint8_t *addr)
{
	return (*addr & 0x01);
}



MODULE_LICENSE("GPL");

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_SUPPORTED_DEVICE(DRIVER_DEVICE);

