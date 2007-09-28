/*
 * Copyright (C) 2006 BATMAN contributors:
 * Thomas Lopatic, Corinna 'Elektra' Aichele, Axel Neumann, Marek Lindner, Andreas Langer
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

#include <linux/version.h>	/* KERNEL_VERSION ... */
#include <linux/fs.h>		/* fops ...*/
#include <linux/inetdevice.h>	/* __in_dev_get_rtnl */
#include <linux/in.h>		/* sockaddr_in */
#include <linux/net.h>		/* socket */
#include <linux/string.h>	/* strlen, strstr, strncmp ... */
#include <linux/ip.h>		/* iphdr */
#include <net/sock.h>		/* sock */
#include <net/pkt_sched.h>	/* class_create, class_destroy, class_device_create */

#include "mod_batgat.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#include <linux/devfs_fs_kernel.h>
#else
	static struct class *batman_class;
#endif

static int batgat_open(struct inode *inode, struct file *filp);
static int batgat_release(struct inode *inode, struct file *file);
static int batgat_ioctl( struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg );

static int udp_server_thread(void *data);
static int register_batgat_device( struct net_device *dev, char *name );
static int unregister_batgat_device( char *name );
static int get_reg_index( char *name );
static int send_data( struct socket *socket, struct sockaddr_in *client, unsigned char *buffer, int buffer_len );
static uint8_t get_virtual_ip( struct reg_device *dev, uint32_t client_addr);


static struct file_operations fops = {
	.open = batgat_open,
 .release = batgat_release,
 .ioctl = batgat_ioctl,
};

static int Major;					/* Major number assigned to our device driver */

static struct reg_device **reg_dev_array=NULL;
static int reg_dev_reserved = 0;			/* memory reserved for elements count */

struct socket *inet_sock;
struct msghdr global_msg;
struct iovec global_iov;
struct sockaddr_in global_addr_out;


int init_module()
{
	/* register our device - kernel assigns a free major number */
	if ( ( Major = register_chrdev( 0, DRIVER_DEVICE, &fops ) ) < 0 ) {

		DBG( "registering the character device failed with %d", Major );
		return Major;

	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	if ( devfs_mk_cdev( MKDEV( Major, 0 ), S_IFCHR | S_IRUGO | S_IWUGO, "batgat", 0 ) )
		DBG( "could not create /dev/batgat" );
#else
	batman_class = class_create( THIS_MODULE, "batgat" );

	if ( IS_ERR( batman_class ) )
		DBG( "could not register class 'batgat'" );
	else
		class_device_create( batman_class, NULL, MKDEV( Major, 0 ), NULL, "batgat" );
#endif


	DBG( "I was assigned major number %d. To talk to", Major );
	DBG( "the driver, create a dev file with 'mknod /dev/batgat c %d 0'.", Major );
	DBG( "Remove the device file and module when done." );

	/* init global socket to forward packets */
	if ( ( sock_create_kern( PF_INET, SOCK_RAW, IPPROTO_RAW, &inet_sock ) ) < 0 ) {

		DBG( "can't create raw socket");
		return 1;

	}

	global_addr_out.sin_family = AF_INET;

	global_msg.msg_iov = &global_iov;
	global_msg.msg_iovlen = 1;
	global_msg.msg_flags = MSG_NOSIGNAL | MSG_DONTWAIT;
	global_msg.msg_name = &global_addr_out;
	global_msg.msg_namelen = sizeof(global_addr_out);
	global_msg.msg_control = NULL;
	global_msg.msg_controllen = 0;
	
	return(0);
}

void cleanup_module()
{
	int ret,i,j;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	devfs_remove( "batgat", 0 );
#else
	class_device_destroy( batman_class, MKDEV( Major, 0 ) );
	class_destroy( batman_class );
#endif

	/* Unregister the device */
	ret = unregister_chrdev( Major, DRIVER_DEVICE );

	if ( ret < 0 )
		DBG( "unregistering the character device failed with %d", ret );

	DBG( "start cleanup reserved %d", reg_dev_reserved );
	for( i = 0 ; i < reg_dev_reserved; i++ ) {

		if( reg_dev_array[ i ] == NULL )
			continue;

		DBG( "clean %s", reg_dev_array[i]->name );

		if( reg_dev_array[ i ]->thread_pid ) {

			kill_proc( reg_dev_array[ i ]->thread_pid, SIGTERM, 0 );
			wait_for_completion( &reg_dev_array[ i ]->thread_complete );

		}

		if(reg_dev_array[i]->client == NULL)
			DBG( "%d client is null", i );
		else {
			for( j = 0; j < 254; j++ ) {
				if( reg_dev_array[ i ]->client[ j ] != NULL )
					kfree( reg_dev_array[ i ]->client[ j ] );
			}
		}

		kfree( reg_dev_array[ i ] );

	}
	
	DBG( "free reg_dev_array" );
	kfree( reg_dev_array );
	reg_dev_reserved -= i;
	
	sock_release( inet_sock );
	DBG( "unload module complete" );
	return;
}

static int batgat_open(struct inode *inode, struct file *filp)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_INC_USE_COUNT;
#else
	try_module_get(THIS_MODULE);
#endif
	return( 0 );

}

static int batgat_release(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_DEC_USE_COUNT;
#else
	module_put(THIS_MODULE);
#endif
	return( 0 );
}


static int batgat_ioctl( struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg )
{
	char *device_name = NULL, *colon_ptr = NULL;
	uint16_t command, length;
	struct net_device *reg_device = NULL;
	int ret_value = 0, reg_ret = 0;

	/* cmd comes with 2 short values */
	command = cmd & 0x0000FFFF;
	length = cmd >> 16;

	if( length > IFNAMSIZ - 1 ) {
		DBG( "device name is too long" );
		ret_value = -EFAULT;
		goto end;
	}
		
	if( command == IOCSETDEV || command == IOCREMDEV ) {

		if( !access_ok( VERIFY_READ, ( void __user* )arg, length ) ) {
			DBG( "cccess to memory area of arg not allowed" );
			ret_value = -EFAULT;
			goto end;
		}

		if( ( device_name = kmalloc( length+1, GFP_KERNEL ) ) == NULL ) {
			DBG( "allocate memory for devicename failed" );
			ret_value = -EFAULT;
			goto end;
		}

		__copy_from_user( device_name, ( void __user* )arg, length );
		device_name[ length ] = 0;

		if ( ( colon_ptr = strchr( device_name, ':' ) ) != NULL )
			*colon_ptr = 0;

		if( ( reg_device = dev_get_by_name( device_name ) ) == NULL ) {
			DBG( "did not find device %s", device_name );
			ret_value = -EFAULT;
			goto end;
		}

		if ( colon_ptr != NULL )
			*colon_ptr = ':';

	}
	
	switch( command ) {

		case IOCSETDEV:

			if( ( reg_ret = register_batgat_device( reg_device, device_name ) ) < 0 )
				ret_value = -EFAULT;

			break;
		case IOCREMDEV:

			if( ( reg_ret = unregister_batgat_device( device_name ) ) < 0 )
				ret_value = -EFAULT;

			break;
		default:
			DBG( "ioctl %d is not supported",command );
			ret_value = -EFAULT;

	}

end:

		if( reg_device )
		dev_put( reg_device );

	if( device_name )
		kfree( device_name );

	return( ret_value );

}

static int register_batgat_device( struct net_device *dev, char *name )
{
	struct in_device *in_dev = NULL;
	struct in_ifaddr **ifap = NULL;
	struct in_ifaddr *ifa = NULL;
	struct sockaddr_in sa;
	struct reg_device *device = NULL;

	int index, i;

	index = get_reg_index( name );

	if( reg_dev_array == NULL || index < 0 ) {

		index = reg_dev_reserved;

		reg_dev_array = krealloc( reg_dev_array, ( sizeof( struct reg_device* )*( reg_dev_reserved + 1) ), GFP_USER );

		if( reg_dev_array == NULL ) {

			DBG( "not enough memory for reg_dev_array" );
			return( -1 );

		}

		reg_dev_array[ index ] = NULL;
		reg_dev_reserved++;

	}

	/* not found in array */
	if( reg_dev_array[ index ] == NULL ) {

		device = kmalloc( sizeof( struct reg_device ), GFP_USER );

		if( device == NULL ) {

			DBG( "not enough memory for reg_device element" );
			return( -2 );

		}

		device->socket = NULL;
		device->thread_pid = 0;
		memset(device->client, 0, sizeof(struct gw_client *) * 254 );
		reg_dev_array[ index ] = device;

	}

	/* init array entry */
	if( device == NULL )
		device = reg_dev_array[ index ];
	
	if( device->thread_pid ) {

		DBG( "found running thread for dev %s", name );
		kill_proc( device->thread_pid, SIGTERM, 0 );
		wait_for_completion( &device->thread_complete );
		DBG( "thread terminated");

	}

	/* if client exist, resest client */
	for( i = 0; i < 254; i++ ) {
		if( device->client[ i ] != NULL ) {
			kfree( device->client[ i ] );
			device->client[ i ] = NULL;
		}
	}

	/* search for interface address */
	if( ( in_dev = __in_dev_get_rtnl( dev ) ) != NULL ) {

		for ( ifap = &in_dev->ifa_list; ( ifa = *ifap ) != NULL; ifap = &ifa->ifa_next ) {

			if ( !strcmp( name, ifa->ifa_label ) )
				break;
			
		}

	} else {

		DBG( "device %s not found", name );
		goto error;

	}

	
	if( ifa == NULL ) {

		DBG( "can't find interface address for %s", name);
		goto error;

	}

	
	if( sock_create_kern( PF_INET, SOCK_DGRAM, IPPROTO_UDP, &device->socket ) < 0 ) {

		DBG( "error creating udp socket for %s", name );
		goto error;

	}

	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = ifa->ifa_local;
	sa.sin_port = htons( (unsigned short)BATMAN_PORT );

	if( device->socket->ops->bind( device->socket, (struct sockaddr *) &sa, sizeof( sa ) ) ) {

		DBG( "can't bind socket");
		sock_release( device->socket );
		goto error;

	}

	strlcpy( device->name, name, strlen( name ) + 1 );
	device->index = index;
	
	init_completion( &device->thread_complete );
	device->thread_pid = kernel_thread( udp_server_thread, (void*)device, CLONE_KERNEL );

	if( device->thread_pid < 0 ) {

		DBG( "can't create thread" );
		sock_release( device->socket );
		goto error;

	}

	return( 0 );

error:

	if( device )	
		kfree( device );

	if( device->socket )
		sock_release( device->socket );

	device = NULL;

	return( -1 );
};

static int unregister_batgat_device( char *name )
{
	struct reg_device *device;
	int i;
	int index = get_reg_index( name );

	if( index < 0 || reg_dev_array[ index ] == NULL )
		return( -1 );

	device = reg_dev_array[ index ];

	if( device->thread_pid ) {

		DBG("wait for sigterm thread...");
		kill_proc( device->thread_pid, SIGTERM, 0 );
		wait_for_completion( &device->thread_complete );
		DBG("thread terminated");

	}

	device->thread_pid = 0;
	
	for( i = 0; i < 254; i++ ) {
		if( device->client[ i ] != NULL )
			kfree( device->client[ i ] );
	}

	kfree( device );
	reg_dev_array[ index ] = NULL;

	return( 0 );
}


static int get_reg_index( char *name )
{
	int free_place = -1, i;
	
	DBG( "search for %s", name );
	
	if( reg_dev_array != NULL ) {

		for( i = 0; i < reg_dev_reserved; i++ ) {

			if( reg_dev_array[ i ] != NULL && strncmp( name, reg_dev_array[i]->name, strlen(name) + 1 ) == 0 ) {

				DBG( "found dev in reg_dev_array");
				return( i );

			} else if( reg_dev_array[ i ] == NULL )
				free_place = i;

		}

	}

	return( free_place );
}

static int udp_server_thread(void *data)
{
	struct reg_device *dev_element = (struct reg_device*)data;
	struct sockaddr_in client;
	struct msghdr msg;
	struct iovec iov;
	struct iphdr *iph;
	unsigned char buffer[1500];
	int len;
	mm_segment_t oldfs;
	uint32_t ip_address;
	unsigned char *check_ip;
	int ret;

	if( dev_element->socket->sk == NULL ) {
		return 0;
	}
	
	msg.msg_name = &client;
	msg.msg_namelen = sizeof( struct sockaddr_in );
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iov    = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = MSG_NOSIGNAL | MSG_DONTWAIT;
	
	DBG( "start udp_server thread for %s", dev_element->name );
	daemonize( "udpserver" );
	allow_signal( SIGTERM );
	while( !signal_pending( current ) ) {

		iov.iov_base = buffer;
		iov.iov_len  = sizeof(buffer);
		oldfs = get_fs();
		set_fs( KERNEL_DS );
		len = sock_recvmsg( dev_element->socket, &msg,sizeof(buffer), 0 );
		set_fs( oldfs );

		if( len > 0 && buffer[0] == TUNNEL_IP_REQUEST ) {

			if( ( ip_address = ( uint8_t )get_virtual_ip( dev_element, client.sin_addr.s_addr ) ) == 0 ) {
				DBG("don't get a virtual ip");
				continue;
			}

			ip_address = 169 + ( 254<<8 ) + ((uint8_t)( dev_element->index )<<16 ) + (ip_address<<24 );
			buffer[0] = TUNNEL_DATA;
			memcpy( &buffer[1], &ip_address, sizeof( ip_address ) );
			send_data( dev_element->socket, &client, buffer, len );

		} else if( len > 0 && buffer[0] == TUNNEL_DATA ) {

			iph = (struct iphdr*)(buffer + 1);

			check_ip = (unsigned char *)&iph->saddr;

			if( check_ip[0] != 169 && check_ip[1] != 254 && dev_element->index != check_ip[2] && dev_element->client[ check_ip[3] ] == NULL ) {
				DBG( "virtual ip %u.%u.%u.%u invalid", check_ip[0], check_ip[1], check_ip[2], check_ip[3] );
				buffer[0] = TUNNEL_IP_INVALID;
				send_data( dev_element->socket, &client, buffer, len );
				continue;
			}
			/* TODO: semaphore */

			global_iov.iov_base = &buffer[1];
			global_iov.iov_len = len - 1;

			global_addr_out.sin_port = 0;
			global_addr_out.sin_addr.s_addr = iph->daddr;

			oldfs = get_fs();
			set_fs( KERNEL_DS );
			ret = sock_sendmsg( inet_sock, &global_msg, len - 1);
			set_fs( oldfs );

		}

	}

	sock_release( dev_element->socket );
	complete( &dev_element->thread_complete );

	return( 0 );
}

static uint8_t get_virtual_ip( struct reg_device *dev, uint32_t client_addr)
{
	
	uint8_t i,first_free = 0;

	for (i = 1; i < 254; i++) {

		if( dev->client[ i ] != NULL ) {
			if( dev->client[ i ]->address == client_addr ) {

				DBG( "client already exists. return %d", i );
				return i;

			}
		} else {
			if ( first_free == 0 )
				first_free = i;
		}

	}


	if ( first_free == 0 ) {
		/* TODO: list is full */
		return -1;

	}

	dev->client[ first_free ] = kmalloc( sizeof( struct gw_client ), GFP_KERNEL );
	/* TODO: check kmalloc */
	dev->client[ first_free ]->address = client_addr;

	/* TODO: check syscall for time*/
	dev->client[ first_free ]->last_keep_alive = 0;

	return first_free;
}

static int send_data( struct socket *socket, struct sockaddr_in *client, unsigned char *buffer, int buffer_len )
{
	struct iovec iov;
	struct msghdr msg;
	mm_segment_t oldfs;

	int error=0,len=0;

	msg.msg_name = NULL;

	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	iov.iov_base = buffer;
	iov.iov_len = buffer_len;
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	msg.msg_flags = MSG_DONTWAIT;

	error = socket->ops->connect( socket, (struct sockaddr *)client, sizeof(*client), 0 );

	if( error != 0 ) {
		DBG("can't connect to socket: %d",error);
		return 0;
	}
	
	oldfs = get_fs();
	set_fs( KERNEL_DS );

	len = sock_sendmsg( socket, &msg, buffer_len );

	if( len < 0 )
		DBG( "sock_sendmsg failed: %d",len);

	set_fs( oldfs );
	return( 0 );
}

MODULE_LICENSE("GPL");

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_SUPPORTED_DEVICE(DRIVER_DEVICE);
