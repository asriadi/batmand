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
#include "batman-adv-interface.h"
#include "batman-adv-send.h"
#include "batman-adv-ttable.h"
#include "batman-adv-log.h"
#include "types.h"
#include "hash.h"
#include <linux/ethtool.h>
#include <linux/etherdevice.h>



#define BAT_HEADER_LEN (sizeof(struct ethhdr) + (sizeof(struct unicast_packet) > sizeof(struct bcast_packet) ? sizeof(struct unicast_packet) : sizeof(struct bcast_packet)))


static int max_mtu;
static uint16_t bcast_seqno = 1; /* give own bcast messages seq numbers to avoid broadcast storms */
static int32_t skb_packets = 0;
static int32_t skb_bad_packets = 0;

unsigned char mainIfAddr[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static unsigned char mainIfAddr_default[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};




static int bat_get_settings(struct net_device *dev, struct ethtool_cmd *cmd);
static void bat_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info);
static u32 bat_get_msglevel(struct net_device *dev);
static void bat_set_msglevel(struct net_device *dev, u32 value);
static u32 bat_get_link(struct net_device *dev);
static u32 bat_get_rx_csum(struct net_device *dev);
static int bat_set_rx_csum(struct net_device *dev, u32 data);


static const struct ethtool_ops bat_ethtool_ops = {
	.get_settings = bat_get_settings,
	.get_drvinfo = bat_get_drvinfo,
	.get_msglevel = bat_get_msglevel,
	.set_msglevel = bat_set_msglevel,
	.get_link = bat_get_link,
	.get_rx_csum = bat_get_rx_csum,
	.set_rx_csum = bat_set_rx_csum
};


void set_main_if_addr(uint8_t *addr)
{
	memcpy(mainIfAddr, addr, ETH_ALEN);
}

int main_if_was_up(void)
{
	return (memcmp(mainIfAddr, mainIfAddr_default, ETH_ALEN) != 0 ? 1 : 0);
}

int my_skb_push(struct sk_buff *skb, unsigned int len)
{
	int result = 0;

	skb_packets++;
	if (skb->data - len < skb->head) {
		skb_bad_packets++;
		result = pskb_expand_head(skb, len, 0, GFP_ATOMIC);

		if (result < 0)
			return result;
	}
	/* TODO: remove this later. it's just for verification. */
	if ((skb_packets & 0xFF) == 0) /* report every 256 packets */
		debug_log(LOG_TYPE_NOTICE, "(%d/%d skbs had to be re-expanded)\n", skb_bad_packets, skb_packets);


	skb_push(skb, len);
	return 0;
}

void interface_setup(struct net_device *dev)
{
	struct bat_priv *priv = netdev_priv(dev);
	char dev_addr[ETH_ALEN];

	ether_setup(dev);

	dev->open = interface_open;
	dev->stop = interface_release;
	dev->get_stats = interface_stats;
	dev->set_mac_address = interface_set_mac_addr;
	dev->change_mtu = interface_change_mtu;
	dev->hard_start_xmit = interface_tx;
	dev->destructor = free_netdev;

	dev->features |= NETIF_F_NO_CSUM;
	dev->mtu -= BAT_HEADER_LEN;
	dev->hard_header_len = ETH_HLEN + BAT_HEADER_LEN; /*reserve more space in the skbuff for our header */

	max_mtu = dev->mtu;

	/* generate random address */
	*(u16 *)dev_addr = htons(0x00FF);
	get_random_bytes(dev_addr + sizeof(u16), 4);
	memcpy(dev->dev_addr, dev_addr, sizeof(dev->dev_addr));

	SET_ETHTOOL_OPS(dev, &bat_ethtool_ops);

	memset(priv, 0, sizeof(struct bat_priv));
}

int interface_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

int interface_release(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

struct net_device_stats *interface_stats(struct net_device *dev)
{
	struct bat_priv *priv = netdev_priv(dev);
	return &priv->stats;
}

int interface_set_mac_addr(struct net_device *dev, void *addr)
{
	return -EBUSY;
}

int interface_change_mtu(struct net_device *dev, int new_mtu)
{
	/* check ranges */
	if ((new_mtu < 68) || (new_mtu > max_mtu))
		return -EINVAL;

	dev->mtu = new_mtu;

	return 0;
}

int interface_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct batman_if *batman_if;
	struct unicast_packet *unicast_packet;
	struct bcast_packet *bcast_packet;
	struct orig_node *orig_node;
	struct ethhdr *ethhdr = (struct ethhdr *)skb->data;
	struct bat_priv *priv = netdev_priv(dev);
	int data_len = skb->len;

	dev->trans_start = jiffies;
	hna_local_add(ethhdr->h_source);

	/* ethernet packet should be broadcasted */
	if (is_bcast(ethhdr->h_dest) || is_mcast(ethhdr->h_dest)) {

		if (my_skb_push(skb, sizeof(struct bcast_packet)) < 0)
			goto dropped;

		bcast_packet = (struct bcast_packet *)skb->data;

		/* batman packet type: broadcast */
		bcast_packet->packet_type = BAT_BCAST;

		/* hw address of first interface is the orig mac because only this mac is known throughout the mesh */
		memcpy(bcast_packet->orig, mainIfAddr, ETH_ALEN);
		/* set broadcast sequence number */

		bcast_packet->seqno = htons(bcast_seqno);

		bcast_seqno++;

		/* broadcast packet */
		rcu_read_lock();
		list_for_each_entry_rcu(batman_if, &if_list, list) {

			send_raw_packet(skb->data, skb->len, batman_if->net_dev->dev_addr, broadcastAddr, batman_if);
		}
		rcu_read_unlock();

	/* unicast packet */
	} else {

		/* get routing information */
		spin_lock(&orig_hash_lock);
		orig_node = ((struct orig_node *)hash_find(orig_hash, ethhdr->h_dest));

		/* check for hna host */
		if (orig_node == NULL)
			orig_node = transtable_search(ethhdr->h_dest);

		if ((orig_node != NULL) && (orig_node->batman_if != NULL) && (orig_node->router != NULL)) {

			if (my_skb_push(skb, sizeof(struct unicast_packet)) < 0)
				goto unlock;

			unicast_packet = (struct unicast_packet *)skb->data;

			/* batman packet type: unicast */
			unicast_packet->packet_type = BAT_UNICAST;
			/* set unicast ttl */
			unicast_packet->ttl = TTL;
			/* copy the destination for faster routing */
			memcpy(unicast_packet->dest, orig_node->orig, ETH_ALEN);

			send_raw_packet(skb->data, skb->len, orig_node->batman_if->net_dev->dev_addr, orig_node->router->addr, orig_node->batman_if);

		} else {

			goto unlock;

		}

		spin_unlock(&orig_hash_lock);
	}

	priv->stats.tx_packets++;
	priv->stats.tx_bytes += data_len;
	goto end;

unlock:
	spin_unlock(&orig_hash_lock);

dropped:
	priv->stats.tx_dropped++;

end:
	kfree_skb(skb);
	return 0;
}

void interface_rx(struct net_device *dev, void *packet, int packet_len)
{
	struct sk_buff *skb;
	struct bat_priv *priv = netdev_priv(dev);

	skb = dev_alloc_skb(packet_len);

	if (!skb) {
		priv->stats.rx_dropped++;
		goto out;
	}

	memcpy(skb_put(skb, packet_len), packet, packet_len);

	/* Write metadata, and then pass to the receive level */
	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev);
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	priv->stats.rx_packets++;
	priv->stats.rx_bytes += packet_len;

	dev->last_rx = jiffies;

	netif_rx(skb);

out:
	return;
}

/* ethtool */
static int bat_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	cmd->supported = 0;
	cmd->advertising = 0;
	cmd->speed = SPEED_10;
	cmd->duplex = DUPLEX_FULL;
	cmd->port = PORT_TP;
	cmd->phy_address = 0;
	cmd->transceiver = XCVR_INTERNAL;
	cmd->autoneg = AUTONEG_DISABLE;
	cmd->maxtxpkt = 0;
	cmd->maxrxpkt = 0;

	return 0;
}

static void bat_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strcpy(info->driver, "B.A.T.M.A.N. Advanced");
	strcpy(info->version, SOURCE_VERSION);
	strcpy(info->fw_version, "N/A");
	strcpy(info->bus_info, "batman");
}

static u32 bat_get_msglevel(struct net_device *dev)
{
	return -EOPNOTSUPP;
}

static void bat_set_msglevel(struct net_device *dev, u32 value)
{
	return;
}

static u32 bat_get_link(struct net_device *dev)
{
	return 1;
}

static u32 bat_get_rx_csum(struct net_device *dev)
{
	return 0;
}

static int bat_set_rx_csum(struct net_device *dev, u32 data)
{
	return -EOPNOTSUPP;
}

