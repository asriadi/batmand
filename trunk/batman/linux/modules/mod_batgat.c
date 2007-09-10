/*
 * Copyright (C) 2006 BATMAN contributors:
 * Andreas Langer
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

/* Kernel Programming */
#define LINUX

#define DRIVER_AUTHOR "Andreas Langer <a.langer@q-dsl.de>, Marek Lindner <lindner_marek@yahoo.de>"
#define DRIVER_DESC   "batman gateway module"
#define DRIVER_DEVICE "batgat"

/* io controls */
#define IOCSETDEV 1
#define IOCREMDEV 2

#define TRANSPORT_PACKET_SIZE 29
#define BATMAN_PORT 4306

#include <linux/module.h>
#include <linux/version.h>
#include <linux/inet.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <net/pkt_sched.h>
#include <net/udp.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	#include <linux/devfs_fs_kernel.h>
#else
	static struct class *batman_class;
#endif

/* tunnel clients */
struct gw_client {
	uint32_t addr;
	uint32_t last_keep_alive;
	uint32_t source;
	unsigned char hw_addr[6];
};

struct dev_element {
	struct list_head list;
	struct net_device *netdev;
	struct packet_type packet;
};

struct gw_element {
	struct list_head list;
	struct gw_client *client[256];
	unsigned short ifindex;
};

static struct list_head device_list;
static struct list_head gw_client_list;


static int batgat_open(struct inode *inode, struct file *filp);
static int batgat_release(struct inode *inode, struct file *file);
static int batgat_ioctl( struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg );
static int batgat_func(struct sk_buff *skb, struct net_device *dv, struct packet_type *pt, struct net_device *orig_dev);

static struct file_operations fops = {
	.open = batgat_open,
	.release = batgat_release,
	.ioctl = batgat_ioctl,
};


static void print_ip(unsigned int sip, unsigned int dip);
static int send_vip(struct sk_buff *skb);
static unsigned short get_virtual_ip(unsigned int ifindex, uint32_t client_addr, uint32_t daddr, unsigned char *mac_source);
static int modify_internet_packet(struct sk_buff *skb, unsigned int addr_part_3,unsigned int addr_part_4);
static void raw_print(void *data, unsigned int length);

static int Major;            /* Major number assigned to our device driver */

static int
batgat_ioctl( struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg )
{
	char *tmp=NULL;
	int command,length,i;
	struct dev_element *dev_entry = NULL;
	struct net_device *rm_dev = NULL;
	struct list_head *ptr = NULL;
	struct gw_element *gw_element = NULL;
	struct list_head *gw_ptr = NULL;
	struct list_head *gw_ptr_tmp = NULL;

	/* cmd comes with 2 short values */
	command = cmd & 0x0000FFFF;
	length = cmd >> 16;

	switch(command)
	{
		case IOCSETDEV:
			if( access_ok(VERIFY_READ, (void __user*)arg, length))
			{
				if( (tmp = kmalloc( length+1, GFP_KERNEL)) == NULL)
				{
					printk("B.A.T.M.A.N. GW: Allocate memory for devicename failed\n");
					return -EFAULT;
				}
				__copy_from_user(tmp, (void __user*)arg, length);
				tmp[length] = 0;
				printk("B.A.T.M.A.N. GW: Register device %s\n", tmp);
				
				if( (dev_entry = kmalloc(sizeof(struct dev_element), GFP_KERNEL)) == NULL) {
					printk("B.A.T.M.A.N. GW: Allocate memory for device list\n");
					if(tmp)
						kfree(tmp);
					return -EFAULT;
				}

				if( (dev_entry->netdev = dev_get_by_name(tmp)) == NULL ) {
					printk("B.A.T.M.A.N. GW: Did not find device %s\n",tmp);
					if(tmp)
						kfree(tmp);
					return -EFAULT;
				}
				
				dev_entry->packet.type = __constant_htons(ETH_P_ALL);
				dev_entry->packet.func = batgat_func;
				
				list_add_tail(&dev_entry->list, &device_list);
				dev_entry->packet.dev = dev_entry->netdev;
				dev_add_pack(&dev_entry->packet);

			} else {

				printk("B.A.T.M.A.N. GW: Access to memory area of arg not allowed\n");
				return -EFAULT;

			}
		    break;
		case IOCREMDEV:
			if( access_ok(VERIFY_READ, (void __user*)arg, length))
			{
				if( (tmp = kmalloc( length+1, GFP_KERNEL)) == NULL)
				{
					printk("B.A.T.M.A.N. GW: Allocate memory for devicename failed\n");
					return -EFAULT;
				}
				__copy_from_user(tmp, (void __user*)arg, length);
				tmp[length] = 0;
				printk("B.A.T.M.A.N. GW: Remove device %s...", tmp);
				
				if((rm_dev = dev_get_by_name(tmp))==NULL) {
					printk("did not find device %s\n",tmp);
					if(tmp)
						kfree(tmp);
					return -EFAULT;
				}

				if(!list_empty(&gw_client_list)) {

					list_for_each_safe(gw_ptr,gw_ptr_tmp,&gw_client_list) {
						gw_element = list_entry(gw_ptr, struct gw_element, list);
						if(gw_element->ifindex == rm_dev->ifindex) {
							for(i=0;i < 255;i++) {
								if(gw_element->client[i] != NULL)
									kfree(gw_element->client[i]);
							}
							list_del(gw_ptr);
							kfree(gw_element);
							break;
						}
					}

				}

				list_for_each(ptr, &device_list) {
					dev_entry = list_entry(ptr, struct dev_element, list);
					if(dev_entry->netdev->ifindex == rm_dev->ifindex)
						break;
				}
				
				if(dev_entry->netdev->ifindex == rm_dev->ifindex) {
					dev_remove_pack(&dev_entry->packet);

					/* we must dev_put for every call of dev_get_by_name */
					dev_put(rm_dev);
					dev_put(dev_entry->netdev);
					
					list_del(&dev_entry->list);
					kfree(dev_entry);
					printk("ok\n");
				} else {
					printk("device %s not in list\n",tmp);
					if(tmp)
						kfree(tmp);
					return -EFAULT;
				}

			} else {

				printk("B.A.T.M.A.N. GW: Access to memory area of arg not allowed\n");
				return -EFAULT;

			}
			break;
		default:
		    return -EINVAL;
    }
	
	if(tmp!=NULL)
		kfree(tmp);

	return(0);
}

int
init_module()
{
// 	int i;
	
	/* register our device - kernel assigns a free major number */
	if ( ( Major = register_chrdev( 0, DRIVER_DEVICE, &fops ) ) < 0 ) {

		printk( "B.A.T.M.A.N. GW: Registering the character device failed with %d\n", Major );
		return Major;

	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	if ( devfs_mk_cdev( MKDEV( Major, 0 ), S_IFCHR | S_IRUGO | S_IWUGO, "batgat", 0 ) ) {
		printk( "B.A.T.M.A.N. GW: Could not create /dev/batgat \n" );
#else
	batman_class = class_create( THIS_MODULE, "batgat" );

	if ( IS_ERR(batman_class) )
		printk( "B.A.T.M.A.N. GW: Could not register class 'batgat' \n" );
	else
		class_device_create( batman_class, NULL, MKDEV( Major, 0 ), NULL, "batgat" );
#endif


	printk( "B.A.T.M.A.N. GW: I was assigned major number %d. To talk to\n", Major );
	printk( "B.A.T.M.A.N. GW: the driver, create a dev file with 'mknod /dev/batgat c %d 0'.\n", Major );
	printk( "B.A.T.M.A.N. GW: Remove the device file and module when done.\n" );
		
	/* init device list */
	INIT_LIST_HEAD(&device_list);
	
	/* init gw_client_list */
	INIT_LIST_HEAD(&gw_client_list);

	return(0);
}

void
cleanup_module()
{
	int ret, i;
	struct gw_element *gw_element = NULL;
	struct list_head *gw_ptr = NULL;
	struct list_head *gw_ptr_tmp = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	devfs_remove( "batgat", 0 );
#else
	class_device_destroy( batman_class, MKDEV( Major, 0 ) );
	class_destroy( batman_class );
#endif

	/* Unregister the device */
	ret = unregister_chrdev( Major, DRIVER_DEVICE );

	if ( ret < 0 )
		printk( "B.A.T.M.A.N. GW: Unregistering the character device failed with %d\n", ret );
	
	if(!list_empty(&gw_client_list)) {

		list_for_each_safe(gw_ptr,gw_ptr_tmp,&gw_client_list) {
			gw_element = list_entry(gw_ptr,struct gw_element,list);

			for(i=0;i < 255;i++) {
				if(gw_element->client[i] != NULL)
					kfree(gw_element->client[i]);
			}
			list_del(gw_ptr);
			kfree(gw_element);
		}

	}

	printk( "B.A.T.M.A.N. GW: Unload complete\n" );
}


static int
batgat_open(struct inode *inode, struct file *filp)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_INC_USE_COUNT;
#else
	try_module_get(THIS_MODULE);
#endif
	return(0);

}

static int 
batgat_release(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_DEC_USE_COUNT;
#else
	module_put(THIS_MODULE);
#endif
	return(0);
}

static int
batgat_func(struct sk_buff *skb, struct net_device *dv, struct packet_type *pt,struct net_device *orig_dev)
{

	struct iphdr *iph = ip_hdr(skb);
	struct udphdr *uhdr;
	unsigned char *buffer;
	unsigned short addr_part_3, addr_part_4;
	
	if(iph->protocol == IPPROTO_UDP && skb->pkt_type == PACKET_HOST) {

		uhdr = (struct udphdr *)(skb->data + sizeof(struct iphdr));
		buffer = (unsigned char*) (skb->data + sizeof(struct iphdr) + sizeof(struct udphdr));
		
		if(ntohs(uhdr->source) == BATMAN_PORT && buffer[0] == 2) {
			
			send_vip(skb);

		} else if(ntohs(uhdr->source) == BATMAN_PORT && buffer[0] == 1) {

			/* TODO: check if source in gw_client_list */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)

			skb_pull(skb,TRANSPORT_PACKET_SIZE);
			skb->network_header = skb->data;
			skb->transport_header = skb->data;
#else
			/* TODO: change pointer for Kernel < 2.6.22 */

#endif
			
		}
		
		
	}
	
	if( ((ntohl(iph->daddr)>>24)&255) == 169) {
		addr_part_3 = (ntohl(iph->daddr)>>8)&255;
		addr_part_4 = ntohl(iph->daddr)&255;

		modify_internet_packet(skb,addr_part_3,addr_part_4);
	}

	kfree_skb(skb);

    return 0;
}

/* helpers */
static int
modify_internet_packet(struct sk_buff *skb, unsigned int addr_part_3,unsigned int addr_part_4) {

	int ret;
	/* size for the udp tunnel */
	int size = sizeof(char)+sizeof(struct udphdr)+sizeof(struct iphdr);

	unsigned char *buffer;
	struct udphdr *uhdr;
	struct iphdr *iph,tmp_iph;
	struct dev_element *dev_entry;
	struct list_head *ptr;
	struct gw_element *gw_element = NULL;
	struct list_head *gw_ptr = NULL;

	list_for_each(ptr, &device_list) {
		dev_entry = list_entry(ptr, struct dev_element, list);
		if(dev_entry->netdev->ifindex == addr_part_3)
			break;
		else
			dev_entry = NULL;
	}

	/* FIXME! store the old iph to use it for the new iph */
	/* it's better to create a new ip header, for performance */
	memcpy(&tmp_iph, ip_hdr(skb), sizeof(struct iphdr));
	
	if(!dev_entry) {
		printk("B.A.T.M.A.N. GW: interface in dev_list with index %d not found\n", addr_part_3);
		return -1;
	}

	if( (ret = pskb_expand_head(skb,size,0,GFP_ATOMIC)) != 0 ) {
		printk("B.A.T.M.A.N. GW: sk_buff header expand failed\n");
		return -1;
	}
	
	/* search if interface index exists in gw_client_list */
	list_for_each(gw_ptr, &gw_client_list) {
		gw_element = list_entry(gw_ptr, struct gw_element, list);
		if(gw_element->ifindex == addr_part_3)
			break;
		else
			gw_element = NULL;
	}

	if(!gw_element) {
		printk("B.A.T.M.A.N. GW: interface in gw_list with index %d not found\n", addr_part_3);
		return -1;
	}

	if(gw_element->client[addr_part_4] == NULL)  {
		printk("B.A.T.M.A.N. GW: client %d not found\n", addr_part_4);
		return -1;
	}


	skb_push(skb,size);

	/* set the pointer new */
	skb_set_mac_header(skb, - sizeof(struct ethhdr));
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb->data = skb->mac_header + sizeof(struct ethhdr);
	
	iph  = ip_hdr(skb);
	uhdr = (struct udphdr *)(skb->data + sizeof(struct iphdr));
	buffer = (unsigned char*)(skb->data + sizeof(struct iphdr) + sizeof(struct udphdr));

	/* FIXME! it's better to create a new ip header, for performance */
	memcpy(iph, &tmp_iph, sizeof(struct iphdr));
	
	iph->daddr = gw_element->client[addr_part_4]->addr;
	iph->saddr = gw_element->client[addr_part_4]->source;

	iph->protocol = IPPROTO_UDP;
	iph->tot_len = htons(skb->len);

	uhdr->source = htons(BATMAN_PORT);
	uhdr->dest = htons(BATMAN_PORT);

	size = skb->len - iph->ihl*4;

	uhdr->len = htons(size);

	uhdr->check = 0;

	ip_send_check(iph);

	buffer[0] = 1;
	skb->dev = dev_entry->netdev;
	
	skb->pkt_type = PACKET_OUTGOING;
	if (skb->dev->hard_header)
		skb->dev->hard_header(skb,skb->dev,ntohs(skb->protocol),gw_element->client[addr_part_4]->hw_addr,skb->dev->dev_addr,skb->len);

	dev_queue_xmit(skb_clone(skb, GFP_ATOMIC));

	return 0;
}

static void
raw_print(void *data, unsigned int length)
{
	unsigned char *buffer = (unsigned char *)data;
	int i;

	printk("\n");
	for(i=0;i<length;i++) {
		if( i == 0 )
			printk("%p| ",&buffer[i]);

		if( i != 0 && i%8 == 0 )
			printk("  ");
		if( i != 0 && i%16 == 0 )
			printk("\n%p| ", &buffer[i]);

		printk("%02x ", buffer[i] );
	}
	printk("\n\n");
}
	
static void
print_ip(unsigned int sip, unsigned int dip)
{
	sip = ntohl(sip);
	dip = ntohl(dip);
	
	printk("%d.%d.%d.%d -> %d.%d.%d.%d\n", (sip >> 24) & 255, (sip >> 16) & 255,(sip >> 8) & 255, (sip & 255),
	       (dip >> 24) & 255, (dip >> 16) & 255,(dip >> 8) & 255, (dip & 255));

	return;
}

static int
send_vip(struct sk_buff *skb)
{

	unsigned int tmp,size;
	unsigned char dst_hw_addr[6];
	unsigned char *buffer = (unsigned char*) (skb->data + sizeof(struct iphdr) + sizeof(struct udphdr));
	struct udphdr *uhdr = (struct udphdr *)(skb->data + sizeof(struct iphdr));
	struct iphdr *iph = ip_hdr(skb);
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)	
	struct ethhdr *eth = (struct ethhdr *)skb_mac_header(skb);
#else
	struct ethhdr *eth = (struct ethhdr *)skb->mac.raw;
#endif	
	
	if((tmp = (unsigned int)get_virtual_ip(skb->dev->ifindex, iph->saddr, iph->daddr,eth->h_source)) == 0) {
		/* TODO: error */
		return -1;
	}

	tmp = 169 + ( 254<<8 ) + ((uint8_t)(skb->dev->ifindex)<<16 ) + (tmp<<24 );

	/* TODO: it's better to memset buffer ? */
	buffer[0] = 1;
	memcpy( &buffer[1], &tmp , sizeof(unsigned int));
	skb->pkt_type = PACKET_OUTGOING;

	/* replace source and destination address */
	tmp = iph->saddr;
	iph->saddr = iph->daddr;
	iph->daddr = tmp;
	
	size = skb->len - iph->ihl*4;
	uhdr->len = htons(size);
	/* don't use checksum */
	uhdr->check = 0;

	ip_send_check(iph);
	
	/* replace mac address for destination */
	memcpy(dst_hw_addr, eth->h_source, 6);
	if (skb->dev->hard_header)
		skb->dev->hard_header(skb,skb->dev,ntohs(skb->protocol),dst_hw_addr,skb->dev->dev_addr,skb->len);
	dev_queue_xmit(skb_clone(skb, GFP_ATOMIC));
	return 0;
}

static unsigned short
get_virtual_ip(unsigned int ifindex, uint32_t client_addr, uint32_t daddr, unsigned char *mac_source)
{
	struct gw_element *gw_element = NULL;
	struct list_head *gw_ptr = NULL;
	uint8_t i,first_free = 0;
	
	/* search if interface index exists in gw_client_list */
	list_for_each(gw_ptr, &gw_client_list) {
		gw_element = list_entry(gw_ptr, struct gw_element, list);
		if(gw_element->ifindex == ifindex)
			goto ifi_found;
	}

	/* create gw_element */
	gw_element = kmalloc(sizeof(struct gw_element), GFP_KERNEL);

	if(gw_element == NULL)
		return 0;
	gw_element->ifindex = ifindex;
	
	for(i=0;i< 255;i++)
		gw_element->client[i] = NULL;
	
	list_add_tail(&gw_element->list, &gw_client_list);

ifi_found:
	/* assign ip */

	for (i = 1;i<255;i++) {
	
		if (gw_element->client[i] != NULL) {

			if ( gw_element->client[i]->addr == client_addr )

				return i;

		} else {

			if ( first_free == 0 )
				first_free = i;

		}

	}

	if ( first_free == 0 ) {
		/* TODO: list is full */
		return -1;

	}

	gw_element->client[first_free] = kmalloc(sizeof(struct gw_client),GFP_KERNEL);
	gw_element->client[first_free]->addr = client_addr;

	/* TODO: check syscall for time*/
	gw_element->client[first_free]->last_keep_alive = 0;

	gw_element->client[first_free]->source = daddr;
	memcpy(gw_element->client[first_free]->hw_addr, mac_source, 6);

	return first_free;
	
}

MODULE_LICENSE("GPL");

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_SUPPORTED_DEVICE(DRIVER_DEVICE);
