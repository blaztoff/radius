/*
 * rlm_decoupled.c
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */
#include <freeradius-devel/ident.h>
RCSID("$Id$")
#include <freeradius-devel/libradius.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <pthread.h>
#include <semaphore.h>
#include <sys/time.h>
#include <unistd.h>

typedef enum { DECOUPLED_PACKET, FINISH, NOOP } item_t;

typedef struct decoupled_packet_item {
	item_t		item_type;
	RADIUS_PACKET   *packet;
	struct decoupled_packet_item *next;
} decoupled_packet_item_t;

typedef struct stat_item {
	int		count;
	time_t		when;
} stat_t;

/*
 *	Define a structure for our module configuration.
 */
typedef struct rlm_decoupled_t {
	fr_ipaddr_t 	src_ipaddr;
	fr_ipaddr_t	src_ip6addr;
	fr_ipaddr_t 	dst_ipaddr;
	fr_ipaddr_t	dst_ip6addr;
	int		src_port;
	int		dst_port;
	char		*secret;
	unsigned char 	requestid;
	pthread_mutex_t mutex;
	sem_t		semaphore;
	int		sockfd;
	decoupled_packet_item_t *decoupled_queue_head;	
	decoupled_packet_item_t *decoupled_queue_tail;
	int		queue_len;
	int		max_messages;

        int             sender_thread_created;
	pthread_t	sender_thread;
	int		messages_per_second;
	int		delay_milliseconds;

	time_t		last_stat_print;
	time_t		print_stat_interval;
	stat_t		queue_high;
	stat_t		last_congestion;
	stat_t		last_dropped;
} rlm_decoupled_t;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
	{ "src_ipaddr", 	PW_TYPE_IPADDR, 	offsetof(rlm_decoupled_t,src_ipaddr.ipaddr.ip4addr), 	NULL, NULL },
	{ "src_ipv6addr", 	PW_TYPE_IPV6ADDR, 	offsetof(rlm_decoupled_t,src_ip6addr.ipaddr.ip6addr), 	NULL, NULL },
	{ "src_port", 		PW_TYPE_INTEGER, 	offsetof(rlm_decoupled_t,src_port), 			NULL, "1815" },
	{ "dst_ipaddr", 	PW_TYPE_IPADDR, 	offsetof(rlm_decoupled_t,dst_ipaddr.ipaddr.ip4addr), 	NULL, NULL },
	{ "dst_ipv6addr", 	PW_TYPE_IPV6ADDR, 	offsetof(rlm_decoupled_t,dst_ip6addr.ipaddr.ip6addr), 	NULL, NULL },
	{ "dst_port", 		PW_TYPE_INTEGER, 	offsetof(rlm_decoupled_t,dst_port), 			NULL, "1813" },
	{ "secret", 		PW_TYPE_STRING_PTR, 	offsetof(rlm_decoupled_t,secret), 			NULL, "secret"},
	{ "max_messages", 	PW_TYPE_INTEGER,    	offsetof(rlm_decoupled_t,max_messages), 		NULL, "1000"},
	{ "messages_per_second",PW_TYPE_INTEGER,    	offsetof(rlm_decoupled_t,messages_per_second), 		NULL, "5"},
	{ "print_stat_interval",PW_TYPE_INTEGER,    	offsetof(rlm_decoupled_t,print_stat_interval), 		NULL, "3600"},
	{ "delay_milliseconds", PW_TYPE_INTEGER,    	offsetof(rlm_decoupled_t,delay_milliseconds), 		NULL, "300"},
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

static void add_packet_to_queue(rlm_decoupled_t *inst, item_t item_type, RADIUS_PACKET *packet, int high_priority); 
static void remove_packet_from_queue(rlm_decoupled_t *inst, item_t* item_type, RADIUS_PACKET** packet);
static void *decoupled_packets_sender_thread(void *instance);
static void print_stats(rlm_decoupled_t *inst);
static int create_packet_sender_thread(rlm_decoupled_t *inst);

/*
 *	Detach an instance and free it's data.
 */
static int decoupled_detach(void *instance)
{
	rlm_decoupled_t	*inst = instance;
	void *result;
	decoupled_packet_item_t *item, *next;

	/* tell the sender thread to quit, put a message at the head of the queue */	
	add_packet_to_queue(inst, FINISH, NULL, 1);
	
	/* wait for it to exit */
	pthread_join(inst->sender_thread, &result);

	/* release the link list and all the allocated memory */
	for (item = inst->decoupled_queue_head; item != NULL; item = next) {
		next = item->next;
		if (item->packet != NULL) free(item->packet);
		free(item);
	}

	/* close socket */
	close(inst->sockfd);
	
	/* destroy mutex and semaphore */
	pthread_mutex_destroy(&inst->mutex);
	sem_destroy(&inst->semaphore);

	/* free and quit */
	free(inst);
	return 0;
}


/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int decoupled_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_decoupled_t	*inst;

	/*
	 *	Set up a storage area for instance data
	 */
	inst = rad_malloc(sizeof(rlm_decoupled_t));
	if (!inst) return -1;
	memset(inst, 0, sizeof(rlm_decoupled_t));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		radlog(L_ERR, "rlm_decoupled: Failed parsing the configuration");
		decoupled_detach(inst);
		return -1;
	}

	/*
	 *	Set up IP type and some defaults 
	 */
	if (cf_section_value_find(conf, "src_ipaddr")) {
		inst->src_ipaddr.af = AF_INET;
	} else if (cf_section_value_find(conf, "src_ip6addr")) {
		inst->src_ipaddr.af = AF_INET6;
	} else {
		ip_hton("127.0.0.1", AF_INET, &inst->src_ipaddr);
	}
	
	if (cf_section_value_find(conf, "dst_ipaddr")) {
		inst->dst_ipaddr.af = AF_INET;
	} else if (cf_section_value_find(conf, "dst_ip6addr")) {
		inst->dst_ipaddr.af = AF_INET6;
	} else {
		ip_hton("127.0.0.1", AF_INET, &inst->dst_ipaddr);
	}
	
	if (!cf_section_value_find(conf, "src_port")) {
		inst->src_port = 1815;
	}

	if (!cf_section_value_find(conf, "dst_port")) {
		inst->src_port = 1813;
	}

	if (!cf_section_value_find(conf, "max_messages")) {
		inst->max_messages = 1000;
	}

	if (!cf_section_value_find(conf, "messages_per_second")) {
		inst->messages_per_second = 5;
	}
	
	if (!cf_section_value_find(conf, "print_stat_interval")) {
		inst->print_stat_interval = 3600;
	}

	if (!cf_section_value_find(conf, "delay_milliseconds")) {
		inst->delay_milliseconds = -1;
	}

   	pthread_mutex_init(&inst->mutex, NULL);
	sem_init(&(inst->semaphore), 0, 0);

	*instance = inst;

	return 0;
}

static int create_packet_sender_thread(rlm_decoupled_t *inst)
{
        pthread_attr_t attr;
        int ret;

        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if ((ret = pthread_create(&inst->sender_thread, NULL, decoupled_packets_sender_thread, inst)) != 0) {
                radlog(L_ERR, "rlm_decoupled: failed to create sender_thread");
                return -1;
        }
        pthread_attr_destroy(&attr);
        return ret;
}

/*
 *  Dispatch an exec method
 */
static int decoupled_dispatch(void *instance, REQUEST *request)
{
	rlm_decoupled_t *inst = (rlm_decoupled_t *) instance;
	RADIUS_PACKET 	*decoupled_packet;

        if (!inst->sender_thread_created) {
                if (create_packet_sender_thread(inst) == 0)
                        inst->sender_thread_created = 1;
        }

	/*
	 *	Allocate the buffer
	 */
	decoupled_packet = malloc(sizeof(*decoupled_packet));
	
	
	/*
	 *     Copy the oridinal packet into the sent packet,
	 *     make sure to mark data as NULL so the rad_send will
	 *     recalculate the authenticator (secret)	
	 */
	memcpy(decoupled_packet, request->packet, sizeof(RADIUS_PACKET));
	decoupled_packet->data = NULL;
	
	/*
	 *	Set the source & destination. 
	 */
	decoupled_packet->src_ipaddr = inst->src_ipaddr;
	decoupled_packet->src_port = inst->src_port;
	decoupled_packet->dst_ipaddr = inst->dst_ipaddr;
	decoupled_packet->dst_port = inst->dst_port;
		
	/*
	 *	Copy the vps (not sure this is required but just to be safe)
	 */
	 
	decoupled_packet->vps = paircopy(request->packet->vps);
	
	/*      pairfree(&request->config_items);
        pairfree(&request->packet->vps);             
        request->username = NULL;
        request->password = NULL;
        pairfree(&request->reply->vps);*/

	
	/* 
	 * now add into the queue 
	 */
	add_packet_to_queue(inst, DECOUPLED_PACKET, decoupled_packet, 0);
		
	return RLM_MODULE_OK;
}


static void *decoupled_packets_sender_thread(void *instance)
{
	rlm_decoupled_t *inst = (rlm_decoupled_t *) instance;
	item_t item_type;
	RADIUS_PACKET *packet;
	struct timeval when, now, sleep;
	int	sleep_usec;
	int	messages_last_second;

	timerclear(&when);

	while (1)
	{
		print_stats(inst);

		/* 
		 * remove from the queue, this will block until a message is available
		 */
		remove_packet_from_queue(inst, &item_type, &packet);
		
		if (item_type == NOOP) {
			continue;
		} 
		else if (item_type == FINISH) {
			pthread_exit(NULL);
		}
		else if (item_type == DECOUPLED_PACKET) {
	        	/*
        	 	 *      See if we need to create a socket
          	 	 */
        		if (inst->sockfd == 0)
        		{
                		inst->sockfd = fr_socket(&inst->src_ipaddr, inst->src_port);
                		if (!inst->sockfd) {
                        		radlog(L_ERR, "rlm_decoupled: can't open a new socket");
                		}
        		}

	        	/*
        	 	 *      Make sure we don't push the into the system more than X messages per second
          	 	 */
			gettimeofday(&now, NULL);
			if (timercmp(&now, &when, >)) {
				gettimeofday(&when, NULL);
				when.tv_sec++;
				messages_last_second = 0;
			}
			else {
				messages_last_second++;
				if (messages_last_second > inst->messages_per_second) {
					/* keep statistics */
					inst->last_congestion.count = messages_last_second;
					inst->last_congestion.when = time(NULL);
					
					/* choose the delay mechanism */
					if (inst->delay_milliseconds != -1) {
                        			radlog(L_INFO, "rlm_decoupled: more than %d per second, delaying in %dms", 
							inst->messages_per_second, inst->delay_milliseconds);
						usleep(1000 * inst->delay_milliseconds);
					}
					else {
						timersub(&when, &now, &sleep);
						sleep_usec = sleep.tv_sec * 1000000 + sleep.tv_usec;
                        			radlog(L_INFO, "rlm_decoupled: more than %d per second, delaying in %d us", 
							inst->messages_per_second, sleep_usec);
						usleep(sleep_usec);
					}
				}
			}

			/*
         	 	 *      Send the packet
         		 */
        	if (packet != NULL) 
			{
				VALUE_PAIR *vp;
				time_t current_time = time(NULL);

				/*
         	 	  	 *      Add to the Acct-Delay-Time
         		  	 */
				if ((packet->timestamp != 0) && (current_time > packet->timestamp)) { 
					vp = pairfind(packet->vps, PW_ACCT_DELAY_TIME);
					if (!vp) {
						vp = paircreate(PW_ACCT_DELAY_TIME, PW_TYPE_INTEGER);
						if (vp) pairadd(&packet->vps, vp);
					}
					if (packet->timestamp != 0) {
						vp->vp_integer += time(NULL) - packet->timestamp;
					}
				}
        			packet->sockfd = inst->sockfd;
        			if (rad_send(packet, NULL, inst->secret)) {
                        	//	radlog(L_ERR, "rlm_decoupled: rad_send failed");
				}
				/*free(packet);*/
				rad_free(&packet);
			}
		}
	}	
}

static void print_stats(rlm_decoupled_t *inst)
{
	time_t		now = time(NULL);

	if (now - inst->last_stat_print > inst->print_stat_interval) {
		inst->last_stat_print = now;
                radlog(L_INFO, "rlm_decoupled: queue_high=%d\t\tat %s", inst->queue_high.count, ctime(&inst->queue_high.when));
                radlog(L_INFO, "rlm_decoupled: last_dropped=%d\t\tat %s", inst->last_dropped.count, ctime(&inst->last_dropped.when));
                radlog(L_INFO, "rlm_decoupled: last_congestion=%d\t\tat %s", inst->last_congestion.count, ctime(&inst->last_congestion.when));
	} 
}


static void add_packet_to_queue(rlm_decoupled_t *inst, item_t item_type, RADIUS_PACKET *packet, int high_priority) 
{
	decoupled_packet_item_t *item;
	
	if ((inst->queue_len >= inst->max_messages) && !high_priority) 
	{
		inst->last_dropped.count = inst->queue_len;
		inst->last_dropped.when = time(NULL);
                radlog(L_ERR, "rlm_decoupled: can't add any more messages, limit is %d", inst->max_messages);
		return;
	}

	item = malloc(sizeof(decoupled_packet_item_t));
	item->item_type = item_type;
	item->packet = packet;
	item->next = NULL;         
	  	
	pthread_mutex_lock(&inst->mutex);

	if (item->packet != NULL)
	{
		item->packet->id = inst->requestid;
		inst->requestid++;
	}

	if (high_priority)
	{
		item->next = inst->decoupled_queue_head;
		if (inst->decoupled_queue_head == NULL) 
                	inst->decoupled_queue_tail = item;
		inst->decoupled_queue_head = item;
	}
	else 
	{
		if (inst->decoupled_queue_head == NULL) 
                	inst->decoupled_queue_head = item;
        else 
					inst->decoupled_queue_tail->next = item;
					
					
        inst->decoupled_queue_tail = item;
 	}
	inst->queue_len++;

	if (inst->queue_high.count < inst->queue_len) {
		inst->queue_high.count = inst->queue_len;
		inst->queue_high.when = time(NULL);
	}

	if (item->packet != NULL)
        	radlog(L_DBG, "rlm_decoupled: adding, queue_len %d, ID %d", inst->queue_len, item->packet->id);
    	else
        	radlog(L_DBG, "rlm_decoupled: adding, queue_len %d", inst->queue_len);

	pthread_mutex_unlock(&inst->mutex);	
	sem_post(&inst->semaphore);

}

static void remove_packet_from_queue(rlm_decoupled_t *inst, item_t* item_type, RADIUS_PACKET** packet)
{
        decoupled_packet_item_t *item;
	struct timespec ts;
	struct timeval	now;

	/* wake up every 2 seconds for housekeeping */
	gettimeofday(&now, NULL);
	ts.tv_sec = now.tv_sec;
	ts.tv_nsec = now.tv_usec * 1000;
	ts.tv_sec += 2;
re_wait:
	if (sem_timedwait(&inst->semaphore, &ts) != 0) {
		if (errno == EINTR) {
			goto re_wait;
		}
		if (errno == ETIMEDOUT) {
	                *item_type = NOOP;
        	        *packet = NULL;
                	return;
		}
		radlog(L_ERR, "rlm_decoupled: sender_thread failed waiting for semaphore: %s: Exiting", strerror(errno));
		return;	
	}

        if (inst->decoupled_queue_head == NULL)
        {
		*item_type = NOOP;
		*packet = NULL;
		return;	
	} 
	
	pthread_mutex_lock(&inst->mutex);

	item = inst->decoupled_queue_head;
	inst->decoupled_queue_head = inst->decoupled_queue_head->next;
	if (inst->decoupled_queue_head == NULL)
		inst->decoupled_queue_tail = NULL;
	
	inst->queue_len--;
	
	*packet = item->packet;
	*item_type = item->item_type;

	if (item->packet != NULL)
        	radlog(L_DBG, "rlm_decoupled: removing, queue_len %d, ID %d", inst->queue_len, item->packet->id);
    	else
        	radlog(L_DBG, "rlm_decoupled: removing, queue_len %d", inst->queue_len);
	
	free(item);
	pthread_mutex_unlock(&inst->mutex);	
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_decoupled = {
	RLM_MODULE_INIT,
	"decoupled",				/* Name */
	RLM_TYPE_CHECK_CONFIG_SAFE, /* type */
	decoupled_instantiate,		/* instantiation */
	decoupled_detach,			/* detach */
	{
		decoupled_dispatch,		/* authentication */
		decoupled_dispatch,	    /* authorization */
		decoupled_dispatch,		/* pre-accounting */
		decoupled_dispatch,		/* accounting */
		NULL,					/* check simul */
		decoupled_dispatch,		/* pre-proxy */
		decoupled_dispatch,		/* post-proxy */
		decoupled_dispatch		/* post-auth */
#ifdef WITH_COA
		, decoupled_dispatch,
		decoupled_dispatch
#endif
	},
};
