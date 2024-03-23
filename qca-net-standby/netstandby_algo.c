/*
 * Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: ISC
 */

/*
 * netstandby_algo.c
 *	NSS algorithm
 */

#include <linux/kernel.h>
#include <linux/netstandby.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <netstandby_nl_if.h>
#include <netstandby_msg_if.h>
#include "netstandby_telemetry.h"
#include "netstandby_main.h"
#include "netstandby_nl_cmn.h"
#include <net/netfilter/nf_conntrack.h>
#include <linux/tick.h>
#include <linux/kernel_stat.h>

#define NETSTANDBY_DNS_PORT	53
#define NETSTANDBY_MCAST_IPV4_ALLHOST_ADDR   0xe0000001 /* 224.0.0.1 */
#define NETSTANDBY_MCAST_IPV4_SSDP_ADDR	0xeffffffa /* 239.255.255.250 */
#define NETSTANDBY_MCAST_IPV4_DNS_ADDR	0xeffffffb /* 239.255.255.251 */
#define NETSTANDBY_MCAST_IPV6_ALLNODES_ADDR	0x2000100	/* ff02:0000:0000:0000:0000:0000:0001:0002 */
#define NETSTANDBY_MCAST_IPV6_NEIGHDIS_ADDR	0xfb000000	/* ff02:0000:0000:0000:0000:0000:0000:00fb */

struct netstandby_erp_nss_telemetry eth_telemetry;

/*
 * netstandby_get_idle_time
 * 	Get the idle time of CPU
 */
static u64 netstandby_get_idle_time(struct kernel_cpustat *kcs, int cpu)
{
        u64 idle, idle_usecs = -1ULL;

        if (cpu_online(cpu))
                idle_usecs = get_cpu_idle_time_us(cpu, NULL);

        if (idle_usecs == -1ULL)
                /* !NO_HZ or cpu offline so we can rely on cpustat.idle */
                idle = kcs->cpustat[CPUTIME_IDLE];
        else
                idle = idle_usecs * NSEC_PER_USEC;

        return idle;
}

/*
 * netstandby_is_flow_not_important
 * 	Returns true if we find that the flow could be a data path flow,
 * 	after filtering out routine network management flows.
 */
bool netstandby_is_flow_not_important(struct nf_conn *ct)
{
	struct nf_conntrack_tuple *orig_tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	int sport, dport;

	sport = ntohs(orig_tuple->src.u.all);
	dport = ntohs(orig_tuple->dst.u.all);

	/*
	 * Ignore loopback, broadcast flows. We also ignore multicast flows that are created in
	 * conntrack table for periodic network management
	 */
	if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num == NFPROTO_IPV4) {
		if (IN_LOOPBACK(ntohl(orig_tuple->src.u3.ip))) {
			return true;
		} else if (IN_MULTICAST(ntohl(orig_tuple->dst.u3.ip))) {
			netstandby_info("Not imp multi IPv4 dst=%pI4\n", &orig_tuple->dst.u3.ip);
			if (ntohl(orig_tuple->dst.u3.ip) == NETSTANDBY_MCAST_IPV4_ALLHOST_ADDR) {
				return true;
			} else if (ntohl(orig_tuple->dst.u3.ip) == NETSTANDBY_MCAST_IPV4_SSDP_ADDR) {
				return true;
			} else if (ntohl(orig_tuple->dst.u3.ip) == NETSTANDBY_MCAST_IPV4_DNS_ADDR) {
				return true;
			}
		} else if (orig_tuple->dst.u3.ip == INADDR_BROADCAST) {
			return true;
		}
	}

	if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num == NFPROTO_IPV6) {
		if (ipv6_addr_is_multicast(&orig_tuple->dst.u3.in6)) {
			netstandby_info("Not imp multicast IPV6 dst=%pI6\n", orig_tuple->dst.u3.ip6);
			if (orig_tuple->dst.u3.in6.s6_addr32[3] == NETSTANDBY_MCAST_IPV6_ALLNODES_ADDR) {
				return true;
			} else if (orig_tuple->dst.u3.in6.s6_addr32[3] == NETSTANDBY_MCAST_IPV6_NEIGHDIS_ADDR) {
				return true;
			}
		} else if (ipv6_addr_loopback(&orig_tuple->src.u3.in6)) {
			return true;
		}
	}

	/*
	 * Ignore DNS flows
	 */
	if (dport == NETSTANDBY_DNS_PORT) {
		return true;
	}

	if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num == NFPROTO_IPV4) {
		netstandby_info("IPV4 imp flow : src=%pI4, dst=%pI4, proto=%u status %ld l3 num %d sport %d dport %d\n",
				&orig_tuple->src.u3.ip,
				&orig_tuple->dst.u3.ip,
				orig_tuple->dst.protonum, ct->status, orig_tuple->src.l3num, ntohs(orig_tuple->src.u.all), ntohs(orig_tuple->dst.u.all));
	}

	if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num == NFPROTO_IPV6) {
		netstandby_info("IPV6 imp flow: src=%pI6, dst=%pI6, proto=%u status %ld l3 num %d sport %d dport %d\n",
				orig_tuple->src.u3.ip6,
				orig_tuple->dst.u3.ip6,
				orig_tuple->dst.protonum, ct->status, orig_tuple->src.l3num, ntohs(orig_tuple->src.u.all), ntohs(orig_tuple->dst.u.all));

	}

	return false;
}

/*
 * netstandby_nss_sampling_timer_cb
 *	Timer to collect the stats of NSS and report it to RM
 */
void netstandby_nss_sampling_work_cb(struct work_struct *work)
{
	struct netstandby_gbl_ctx *gbl_ctx = &gbl_netstandby_ctx;
	struct net_device *dev;
	uint8_t i = 0;
	int bucket = 0;
	struct nf_conn *ct;
	struct nf_conntrack_tuple_hash *h;
	struct hlist_nulls_node *n;
	struct kernel_cpustat *kcs;
	const struct rtnl_link_stats64 *dev_stats;
	struct rtnl_link_stats64 temp;

	/*
	 * Rate analysis
	 * Compute the difference between prev and curr bytes/pkts
	 */
	for (i = 0; i < NSS_DP_MAX_INTERFACES - 1; i++) {
		dev = (struct net_device *)gbl_ctx->ethinfo[i].netdev;
		if (!dev) {
			netstandby_info("dev is NULL i %d\n", i);
			continue;
		}

		dev_stats = dev_get_stats(dev, &temp);
		gbl_ctx->nss_sample.curr_eth_sample[i].cur_tx_bytes = dev_stats->tx_bytes;
		gbl_ctx->nss_sample.curr_eth_sample[i].cur_rx_bytes = dev_stats->rx_bytes;
		gbl_ctx->nss_sample.curr_eth_sample[i].cur_tx_packets = dev_stats->tx_packets;
		gbl_ctx->nss_sample.curr_eth_sample[i].cur_rx_packets = dev_stats->rx_packets;
		eth_telemetry.ethstats[i].tx_bytes_diff = gbl_ctx->nss_sample.curr_eth_sample[i].cur_tx_bytes - gbl_ctx->nss_sample.curr_eth_sample[i].prev_tx_bytes;
		eth_telemetry.ethstats[i].rx_bytes_diff = gbl_ctx->nss_sample.curr_eth_sample[i].cur_rx_bytes - gbl_ctx->nss_sample.curr_eth_sample[i].prev_rx_bytes;

		eth_telemetry.ethstats[i].tx_pkts_diff = gbl_ctx->nss_sample.curr_eth_sample[i].cur_tx_packets - gbl_ctx->nss_sample.curr_eth_sample[i].prev_tx_packets;
		eth_telemetry.ethstats[i].rx_pkts_diff = gbl_ctx->nss_sample.curr_eth_sample[i].cur_rx_packets - gbl_ctx->nss_sample.curr_eth_sample[i].prev_rx_packets;
		gbl_ctx->nss_sample.curr_eth_sample[i].prev_tx_bytes = gbl_ctx->nss_sample.curr_eth_sample[i].cur_tx_bytes;
		gbl_ctx->nss_sample.curr_eth_sample[i].prev_rx_bytes = gbl_ctx->nss_sample.curr_eth_sample[i].cur_rx_bytes;
		gbl_ctx->nss_sample.curr_eth_sample[i].prev_tx_packets = gbl_ctx->nss_sample.curr_eth_sample[i].cur_tx_packets;
		gbl_ctx->nss_sample.curr_eth_sample[i].prev_rx_packets = gbl_ctx->nss_sample.curr_eth_sample[i].cur_rx_packets;
		memcpy(&eth_telemetry.ethstats[i].dev_name, dev->name, sizeof(eth_telemetry.ethstats[i].dev_name));
		netstandby_info("Dev:%s Tx bytes %llu Rx bytes %llu Tx pkts %llu Rx pkts %llu\n", eth_telemetry.ethstats[i].dev_name, eth_telemetry.ethstats[i].tx_bytes_diff, eth_telemetry.ethstats[i].rx_bytes_diff, eth_telemetry.ethstats[i].tx_pkts_diff, eth_telemetry.ethstats[i].rx_pkts_diff);
	}
	eth_telemetry.num_of_ifaces = i;
	netstandby_info("Number of ifaces %d\n", eth_telemetry.num_of_ifaces);

	/*
	 * CPU utilization analysis
	 * 	Per CPU utilization logic
	 */
	for_each_possible_cpu(i) {
		kcs = &kcpustat_cpu(i);
		gbl_ctx->nss_sample.curr_cpuutil_sample[i].curr_time = ktime_get_real_ns();
		gbl_ctx->nss_sample.curr_cpuutil_sample[i].current_idle_sec = netstandby_get_idle_time(kcs, i);

		/*
		 * Calculate the non idle time in the NSS sample timer value
		 */
		eth_telemetry.cpuutil_telemetry[i].non_idle_time = (gbl_ctx->nss_sample.curr_cpuutil_sample[i].curr_time - gbl_ctx->nss_sample.curr_cpuutil_sample[i].prev_time) - (gbl_ctx->nss_sample.curr_cpuutil_sample[i].current_idle_sec - gbl_ctx->nss_sample.curr_cpuutil_sample[i].previous_idle_sec);
		netstandby_info("CPU:%d prev time %llu cur time %llu prev idle %llu curr idle %llu non idle %llu\n", i, gbl_ctx->nss_sample.curr_cpuutil_sample[i].prev_time, gbl_ctx->nss_sample.curr_cpuutil_sample[i].curr_time, gbl_ctx->nss_sample.curr_cpuutil_sample[i].previous_idle_sec, gbl_ctx->nss_sample.curr_cpuutil_sample[i].current_idle_sec, eth_telemetry.cpuutil_telemetry[i].non_idle_time);
		gbl_ctx->nss_sample.curr_cpuutil_sample[i].prev_time = gbl_ctx->nss_sample.curr_cpuutil_sample[i].curr_time;
		gbl_ctx->nss_sample.curr_cpuutil_sample[i].previous_idle_sec = gbl_ctx->nss_sample.curr_cpuutil_sample[i].current_idle_sec;
	}

	/*
	 * Iface up analysis
	 */
	eth_telemetry.eth_link_up.prev_link_up = eth_telemetry.eth_link_up.curr_link_up;
	eth_telemetry.eth_link_up.curr_link_up = 0;

	for (i = 0; i < NSS_DP_MAX_INTERFACES-1; i++) {
		dev = (struct net_device *)gbl_ctx->ethinfo[i].netdev;
		/*
		 * Checks whether the iface is up or not
		 */
		if (netif_oper_up(dev)) {
			eth_telemetry.eth_link_up.curr_link_up++;
		}

	}
	netstandby_info("New link up curr up dev %d prev up dev %d\n", eth_telemetry.eth_link_up.curr_link_up,
			eth_telemetry.eth_link_up.prev_link_up);

	/*
	 * Level#4 analysis
	 * Iteration of nf conntrach
	 * init_net.ct.count gives the total number of nf conntrack entries
	 * If the number of conn track is more than max, then NSS is in non idle state
	 */
	eth_telemetry.num_of_nf_ct = atomic_read(&init_net.ct.count);

	eth_telemetry.ct_data_flows.prev_ct_data_flow_cnt = eth_telemetry.ct_data_flows.curr_ct_data_flow_cnt;
	eth_telemetry.ct_data_flows.curr_ct_data_flow_cnt = 0;
	for (bucket = 0; bucket < nf_conntrack_htable_size; bucket++) {
		/*
		 * Loop through each entry in the bucket
		 */
		hlist_nulls_for_each_entry(h, n, &nf_conntrack_hash[bucket],
				hnnode) {
			/*
			 * Check the CT for IP_CT_DIR_ORIGINAL dir alone
			 */
			if (NF_CT_DIRECTION(h)) {
				continue;
			}
			ct = nf_ct_tuplehash_to_ctrack(h);
			if (netstandby_is_flow_not_important(ct)) {
				continue;
			}
			eth_telemetry.ct_data_flows.curr_ct_data_flow_cnt++;
		}
	}

	netstandby_info("Curr imp ct %d Prev imp ct %d nf ct %u\n", eth_telemetry.ct_data_flows.prev_ct_data_flow_cnt,
			eth_telemetry.ct_data_flows.curr_ct_data_flow_cnt, atomic_read(&init_net.ct.count));
	/*
	 * Send the NSS telemetry to RM
	 */
	if (netstandby_nss_telemetry_to_rm(&eth_telemetry)) {
		schedule_delayed_work(&gbl_ctx->nss_sample.sampling_work,
				msecs_to_jiffies(gbl_ctx->nss_sample.sampling_time_millisec));
	} else {
		netstandby_warn("Telemetry to ERP service is failed\n");
	}
}
