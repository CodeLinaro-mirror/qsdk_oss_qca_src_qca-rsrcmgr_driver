/*
 * Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: ISC
 */

#include <linux/kernel.h>
#include <linux/netstandby.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/timer.h>
#include <net/genetlink.h>
#include <net/sock.h>
#include "netstandby_telemetry.h"
#include <netstandby_nl_if.h>
#include <net/neighbour.h>
#include "netstandby_main.h"
#include <linux/time.h>
#include <net/netevent.h>
#include <linux/ktime.h>
#include <linux/rtc.h>

bool first = true;

/*
 * netstandby_get_bucket_index
 * 	returns the index of bucket based on the current hour
 */
int netstandby_get_bucket_index(int hour) {

	if ((hour >= 0) && (hour < NETSTANDBY_TELEMETRY_HOUR_SIX)) {
		return NETSTANDBY_LAN_CLIENT_PERIOD_12AM_TO_6AM;
	} else if  ((hour >= NETSTANDBY_TELEMETRY_HOUR_SIX) && (hour < NETSTANDBY_TELEMETRY_HOUR_TWELVE)) {
		return NETSTANDBY_LAN_CLIENT_PERIOD_6AM_TO_12PM;
	} else if  ((hour >= NETSTANDBY_TELEMETRY_HOUR_TWELVE) && (hour < NETSTANDBY_TELEMETRY_HOUR_EIGHTEEN)) {
		return NETSTANDBY_LAN_CLIENT_PERIOD_12PM_TO_6PM;
	} else {
		return NETSTANDBY_LAN_CLIENT_PERIOD_6PM_TO_12AM;
	}
}

/*
 * netstandby_telemetry_cb
 * 	Cb to update the client connection instance for every 6 hours
 */
void netstandby_lan_telemetry_cb(struct work_struct *work) {
	struct netstandby_gbl_ctx *gbl_ctx;
	int index;
	struct rtc_time t;

	t = rtc_ktime_to_tm(ktime_get_real());
	gbl_ctx = &gbl_netstandby_ctx;
	index = netstandby_get_bucket_index(t.tm_hour);

	if (index == NETSTANDBY_LAN_CLIENT_PERIOD_12AM_TO_6AM) {
		gbl_ctx->lan_telemetry[index].total_active_lan_clients = gbl_ctx->lan_telemetry[NETSTANDBY_LAN_CLIENT_PERIOD_6PM_TO_12AM].lan_client_connect_events - gbl_ctx->lan_telemetry[NETSTANDBY_LAN_CLIENT_PERIOD_6PM_TO_12AM].lan_client_disconnect_events;
	} else {
		gbl_ctx->lan_telemetry[index].total_active_lan_clients = gbl_ctx->lan_telemetry[index-1].lan_client_connect_events - gbl_ctx->lan_telemetry[index-1].lan_client_disconnect_events;
	}

	first = false;
	netstandby_lan_telemetry_stats_to_rm(gbl_ctx->lan_telemetry);
	schedule_delayed_work(&gbl_ctx->lan_telemetry_work, jiffies + NETSTANDBY_TELEMETRY_SIX_HOURS);
}

/*
 * netstandby_neigh_netevent_callback
 * 	Callback for processing the neigh event from neigh module (core kernel)
 */
int netstandby_telemetry_neigh_netevent_callback(struct notifier_block *notifier, unsigned long event, void *ctx)
{
	struct netstandby_gbl_ctx *gbl_ctx;
	struct net_device *dev;
	struct rtc_time t;
	int index, i = 0;

	dev = (struct net_device *)ctx;
	t = rtc_ktime_to_tm(ktime_get_real());
	index = netstandby_get_bucket_index(t.tm_hour);
	gbl_ctx = &gbl_netstandby_ctx;

	if ((!gbl_ctx->nss_sample.sampling_time_millisec) || (!event)) {
		netstandby_info("ERP service is disabled or invalid event:%lu\n", event);
		return -1;
	}

	for (i = 0; i < gbl_ctx->wan_iface_cnt; i++) {
		if (!memcmp(&gbl_ctx->wan_intf[i], dev->name, sizeof(dev->name))) {
			netstandby_info("Received the event from WAN iface. Hence, ignoring\n");
			/*
			 * For WAN ifaces, stats will not considered
			 */
			return NOTIFY_DONE;
		}
	}

	if (event == NEIGH_EVENT_NOTIFY_ADD) {
		gbl_ctx->lan_telemetry[index].lan_client_connect_events++;
		/*
		 * Below check is added to update clients_conn_events for first bucket and for the subseuqent slots,
		 * clients_conn_events will be updated by 6 hour delayed worker thread
		 */
		if (first) {
			gbl_ctx->lan_telemetry[index].total_active_lan_clients++;
		}
	}

	if (event == NEIGH_EVENT_NOTIFY_DELETE) {
		gbl_ctx->lan_telemetry[index].lan_client_disconnect_events++;
	}

	netstandby_info("Event %lu Bucket %d New_Cli_conn %u Total active lan clients %u cli_disconn %u\n",event, index, gbl_ctx->lan_telemetry[index].lan_client_connect_events, gbl_ctx->lan_telemetry[index].total_active_lan_clients, gbl_ctx->lan_telemetry[index].lan_client_disconnect_events);
	netstandby_lan_telemetry_stats_to_rm(gbl_ctx->lan_telemetry);
	return NOTIFY_DONE;
}

