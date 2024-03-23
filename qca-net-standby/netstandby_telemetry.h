/*
 * Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: ISC
 */

#ifndef __NETSTANDBY_TELEMETRY_H
#define __NETSTANDBY_TELEMETRY_H

#include <linux/kernel.h>
#include <linux/netstandby.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/timer.h>
#include <net/genetlink.h>
#include <net/sock.h>

#define NETSTANDBY_TELEMETRY_HOUR_SIX	6
#define NETSTANDBY_TELEMETRY_HOUR_TWELVE     12
#define NETSTANDBY_TELEMETRY_HOUR_EIGHTEEN        18
#define NETSTANDBY_TELEMETRY_SIX_HOURS  (6 * 60 * 60 * HZ)

int netstandby_telemetry_neigh_netevent_callback(struct notifier_block *notifier, unsigned long event, void *ctx);

#endif
