/*
 * socketdaemon/main.c
 *
 * Unix Domain Socket daemon for Enigma2 / OpenATV.
 * Listens on /var/run/daemon.socket (AF_UNIX SOCK_STREAM).
 *
 * Protocol (null-terminated strings):
 *   Client sends:  "<COMMAND>[,<data>]\0"
 *   Daemon replies: "RC:<exitcode>"  (0 = success, 127 = unknown command)
 *
 * Supported commands:
 *   RESTART,<service>         → /etc/init.d/<service> restart
 *   START,<service>           → /etc/init.d/<service> start
 *   STOP,<service>            → /etc/init.d/<service> stop
 *   SWITCH_SOFTCAM,<name>     → stop + re-link + start softcam
 *   SWITCH_CARDSERVER,<name>  → stop + re-link + start cardserver
 *   NETRESTART                → netrestarter restart all
 *   NETRESTART,<iface>        → netrestarter restart <iface>
 *                               (iface: eth0, wlan0, wlan1, …)
 *   PING,<iface>,<host>       → one ICMP echo bound to <iface>, 2s timeout
 *                               (exitcode 0 = reply received, 1 = no reply)
 *   RESOLVE,<host>            → resolve <host> via getaddrinfo (AF_INET)
 *                               (exitcode 0 = resolved, 1 = failed)
 *   NETSCAN,<cidr>,<port>[,<port>...]
 *                             → active TCP connect-scan of <cidr> (max /24,
 *                               i.e. up to 256 host addresses) against the
 *                               given ports, writes /var/run/netscan
 *                               (exitcode 0 = scan completed, 1 = bad params).
 *                               Blocks the caller for the scan's duration
 *                               (bounded, see NETSCAN block below) - same
 *                               blocking-per-command model as PING above.
 *
 * In addition to on-demand NETSCAN, the daemon runs its own unattended
 * discovery scan once at startup (SMB/NFS ports 445+2049 against the
 * default-route interface's subnet), after waiting for that interface to
 * have a usable IPv4 address - see nm_run_autoscan().
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>

#define CMD_SOCKET_NAME "/var/run/daemon.socket"
#define CMD_START "START"
#define CMD_STOP "STOP"
#define CMD_RESTART "RESTART"
#define CMD_SWITCH_CAM "SWITCH_SOFTCAM"
#define CMD_SWITCH_CARDSERVER "SWITCH_CARDSERVER"
#define CMD_NETRESTART "NETRESTART"
#define NETRESTARTER_SH      "/etc/init.d/netrestarter"
#define NET_SOCKET_NAME          "/var/run/daemon_net.socket"
#define NETLINK_KOBJECT_UEVENT   15

#define CMD_IFUP "IFUP"
#define CMD_IFDOWN "IFDOWN"
#define CMD_WLANUP "WLANUP"
#define CMD_WLANDOWN "WLANDOWN"
#define WLANACTIVATOR_SH "/etc/init.d/wlanactivator"
#define CMD_PING "PING"
#define CMD_RESOLVE "RESOLVE"
#define CMD_NETSCAN "NETSCAN"

/* network monitor */
#define NETINFO_PATH      "/var/run/netinfo"
#define NETINFO_TMP       "/var/run/netinfo.tmp"

/* Safety fallback interval – only fires if kernel emits no events (e.g.
 * DHCP renewal on kernel 3.14 does not generate RTMGRP_IPV4_IFADDR).
 * select() is blocking, so this costs zero CPU while waiting. */
#define POLL_INTERVAL_SEC 120
#define NETMON_BUF_SIZE   8192

/*
 * Minimal wireless ioctl definitions – avoids linux/wireless.h header
 * conflicts with net/if.h on older glibc/kernel header combinations.
 */
#ifndef SIOCGIWNAME
#define SIOCGIWNAME  0x8B01
#endif
#ifndef SIOCGIWFREQ
#define SIOCGIWFREQ  0x8B05
#endif
#ifndef SIOCGIWSTATS
#define SIOCGIWSTATS 0x8B0F
#endif
#ifndef SIOCGIWAP
#define SIOCGIWAP    0x8B15
#endif
#ifndef SIOCGIWESSID
#define SIOCGIWESSID 0x8B1B
#endif
#ifndef SIOCGIWRATE
#define SIOCGIWRATE  0x8B21
#endif
#define NM_IW_ESSID_MAX  32
#define NM_IW_QUAL_DBM   0x08

struct nm_iw_quality { uint8_t qual, level, noise, updated; };
struct nm_iw_stats   { uint16_t status; struct nm_iw_quality qual; };
struct nm_iw_point   { void *pointer; uint16_t length, flags; };
union  nm_iwreq_data {
	char name[IFNAMSIZ];
	struct nm_iw_point essid;
	struct { void *pointer; uint16_t length, flags; } data;
	struct { uint16_t sa_family; uint8_t sa_data[14]; } ap_addr; /* SIOCGIWAP  */
	struct { int32_t m; int16_t e; uint8_t i; uint8_t flags; } freq; /* SIOCGIWFREQ */
	struct { int32_t value; uint8_t fixed; uint8_t disabled; uint16_t flags; } param; /* SIOCGIWRATE */
};
struct nm_iwreq      { char iw_ifname[IFNAMSIZ]; union nm_iwreq_data u; };

/*
 * Minimal Generic Netlink / nl80211 definitions – hand-rolled like the
 * wireless-extension ioctls above, to avoid depending on linux/nl80211.h
 * and linux/genetlink.h, which aren't guaranteed present/consistent across
 * the many cross-compilation kernel header sets this daemon is built with.
 */
#define NM_NETLINK_GENERIC          16
#define NM_GENL_ID_CTRL             0x10
#define NM_CTRL_CMD_GETFAMILY       3
#define NM_CTRL_ATTR_FAMILY_ID      1
#define NM_CTRL_ATTR_FAMILY_NAME    2
#define NM_NL80211_CMD_GET_STATION      17
#define NM_NL80211_ATTR_IFINDEX         3
#define NM_NL80211_ATTR_MAC             6
#define NM_NL80211_ATTR_STA_INFO        21
#define NM_NL80211_STA_INFO_TX_BITRATE  8
#define NM_NL80211_RATE_INFO_BITRATE    1
#define NM_NL80211_RATE_INFO_BITRATE32  5

struct nm_genlmsghdr { uint8_t cmd, version; uint16_t reserved; };

static int verbose = 0;
static volatile sig_atomic_t running = 1;
static pthread_t g_monitor_tid;
static int g_stop_pipe[2] = {-1, -1};

/* Serializes access to the netscan machinery's static scan/DNS-cache
 * buffers (see NETSCAN block below) between two independent callers that
 * run on different threads: CMD_NETSCAN (processMessage(), on the main
 * accept-loop thread) and nm_run_autoscan() (on its own thread, spawned
 * once by monitor_thread() at startup). */
static pthread_mutex_t g_netscan_mutex = PTHREAD_MUTEX_INITIALIZER;

int processMessage(char *inData);
static void *monitor_thread(void *arg);
static void *nm_autoscan_thread(void *arg);

static FILE *log_stream;

static void handle_signal(int sig)
{
	(void)sig;
	running = 0;
	/* wake monitor thread out of select() immediately */
	if (g_stop_pipe[1] >= 0) {
		char b = 0;
		(void)write(g_stop_pipe[1], &b, 1);
	}
}

void LOG(const char *format, ...)
{
	char buf[2048];
	char timebuf[50];
	va_list other_args;
	time_t t;
	struct tm *tm;
	va_start(other_args, format);
	vsnprintf(buf, sizeof(buf), format, other_args);
	va_end(other_args);

	time(&t);
	tm = gmtime(&t);

	if (tm)
	{
		strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", tm);
		fprintf(log_stream, "[%s] %s", timebuf, buf);
	}
	else
	{
		fprintf(log_stream, "%s", buf);
	}
	fflush(log_stream);
}


/* ============================================================
 * Network monitor helpers
 * ============================================================ */

/* VPN tunnels (WireGuard, OpenVPN tun/tap, PPP) show up as regular
 * point-to-point interfaces in /proc/net/dev; tell them apart from
 * physical links via IFF_POINTOPOINT plus the usual name prefixes. */
static int nm_is_vpn(short flags, const char *iface)
{
	if (flags & IFF_POINTOPOINT)
		return 1;
	return !strncmp(iface, "wg", 2) || !strncmp(iface, "tun", 3) ||
	       !strncmp(iface, "tap", 3) || !strncmp(iface, "ppp", 3) ||
	       !strncmp(iface, "zt", 2);
}

static int nm_is_wireless(int sock, const char *iface)
{
	struct nm_iwreq wrq;
	memset(&wrq, 0, sizeof(wrq));
	strncpy(wrq.iw_ifname, iface, IFNAMSIZ - 1);
	return ioctl(sock, SIOCGIWNAME, &wrq) >= 0;
}

static int nm_get_link(int sock, const char *iface)
{
	struct ifreq ifr;
	struct ethtool_value ev;
	memset(&ifr, 0, sizeof(ifr));
	memset(&ev,  0, sizeof(ev));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	ev.cmd = ETHTOOL_GLINK;
	ifr.ifr_data = (void *)&ev;
	if (ioctl(sock, SIOCETHTOOL, &ifr) < 0)
		return -1;
	return (int)ev.data;
}

static const char *nm_port_str(uint8_t port)
{
	switch (port) {
	case 0x00: return "TP";
	case 0x01: return "AUI";
	case 0x02: return "MII";
	case 0x03: return "FIBRE";
	case 0x04: return "BNC";
	case 0x05: return "DA";
	default:   return NULL;
	}
}

static void nm_get_eth_info(int sock, const char *iface,
                            int *speed, int *duplex,
                            int *port, int *xcvr, int *autoneg,
                            uint32_t *supported)
{
	struct ifreq ifr;
	struct ethtool_cmd ecmd;
	*speed     = -1;
	*duplex    = -1;
	*port      = -1;
	*xcvr      = -1;
	*autoneg   = -1;
	*supported = 0;
	memset(&ifr,  0, sizeof(ifr));
	memset(&ecmd, 0, sizeof(ecmd));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	ecmd.cmd = ETHTOOL_GSET;
	ifr.ifr_data = (void *)&ecmd;
	if (ioctl(sock, SIOCETHTOOL, &ifr) < 0)
		return;
	*speed     = (int)ethtool_cmd_speed(&ecmd);
	*duplex    = (int)ecmd.duplex;      /* 0=half, 1=full */
	*port      = (int)ecmd.port;
	*xcvr      = (int)ecmd.transceiver;
	*autoneg   = (int)ecmd.autoneg;     /* 0=off, 1=on */
	*supported = ecmd.supported;        /* SUPPORTED_* bitmask */
}

static void nm_get_wlan_ssid(int sock, const char *iface, char *out, size_t outsz)
{
	struct nm_iwreq wrq;
	out[0] = '\0';
	memset(&wrq, 0, sizeof(wrq));
	strncpy(wrq.iw_ifname, iface, IFNAMSIZ - 1);
	wrq.u.essid.pointer = out;
	wrq.u.essid.length  = (uint16_t)(outsz - 1);
	wrq.u.essid.flags   = 0;
	if (ioctl(sock, SIOCGIWESSID, &wrq) >= 0) {
		size_t len = wrq.u.essid.length < outsz - 1 ? wrq.u.essid.length : outsz - 1;
		out[len] = '\0';
	} else {
		out[0] = '\0';
	}
}

static int nm_get_wlan_signal(int sock, const char *iface)
{
	struct nm_iwreq wrq;
	struct nm_iw_stats stats;
	memset(&wrq,   0, sizeof(wrq));
	memset(&stats, 0, sizeof(stats));
	strncpy(wrq.iw_ifname, iface, IFNAMSIZ - 1);
	wrq.u.data.pointer = &stats;
	wrq.u.data.length  = sizeof(stats);
	wrq.u.data.flags   = 1;
	if (ioctl(sock, SIOCGIWSTATS, &wrq) < 0)
		return 0;
	if (stats.qual.updated & NM_IW_QUAL_DBM)
		return (int)(int8_t)stats.qual.level;
	/* raw hardware value: >63 is typically unsigned dBm offset */
	return stats.qual.level > 63 ? (int)stats.qual.level - 256 : (int)stats.qual.level;
}

/* BSSID (AP MAC) via SIOCGIWAP; returns 1 on success */
static int nm_get_wlan_bssid(int sock, const char *iface, char *out, size_t outsz)
{
	struct nm_iwreq wrq;
	memset(&wrq, 0, sizeof(wrq));
	strncpy(wrq.iw_ifname, iface, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIWAP, &wrq) < 0)
		return 0;
	const uint8_t *b = wrq.u.ap_addr.sa_data;
	/* all-zero or ff:ff:ff:ff:ff:ff = not associated */
	int allzero = 1, allff = 1;
	for (int i = 0; i < 6; i++) {
		if (b[i] != 0x00) allzero = 0;
		if (b[i] != 0xff) allff   = 0;
	}
	if (allzero || allff)
		return 0;
	snprintf(out, outsz, "%02x:%02x:%02x:%02x:%02x:%02x",
	         b[0], b[1], b[2], b[3], b[4], b[5]);
	return 1;
}

/* Frequency in MHz via SIOCGIWFREQ; returns 0 when not available */
static int nm_get_wlan_freq_mhz(int sock, const char *iface)
{
	struct nm_iwreq wrq;
	memset(&wrq, 0, sizeof(wrq));
	strncpy(wrq.iw_ifname, iface, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIWFREQ, &wrq) < 0)
		return 0;
	int32_t m = wrq.u.freq.m;
	int16_t e = wrq.u.freq.e;
	if (m <= 0 || e < 0)
		return 0; /* channel index or invalid */
	/* convert m * 10^e Hz → MHz */
	while (e > 6) { m *= 10; e--; }
	while (e < 6) { m /= 10; e++; }
	return (int)m;
}

/* Appends one netlink attribute (type+len+data, 4-byte aligned) to buf at
 * off; returns the new offset. Reuses struct rtattr / RTA_* macros from
 * linux/rtnetlink.h - identical binary layout to generic-netlink's nlattr. */
static size_t nm_nl_put(void *buf, size_t off, unsigned short type, const void *data, size_t len)
{
	struct rtattr *rta = (struct rtattr *)((char *)buf + off);
	rta->rta_type = type;
	rta->rta_len  = RTA_LENGTH(len);
	memcpy(RTA_DATA(rta), data, len);
	return off + RTA_ALIGN(rta->rta_len);
}

/* Resolves the nl80211 generic-netlink family id once; cached for the
 * process lifetime. Returns -1 if generic netlink / nl80211 is unavailable. */
static int nm_nl80211_family_id(void)
{
	static int cached = -2; /* -2 = not yet resolved */
	if (cached != -2)
		return cached;
	cached = -1;

	int sock = socket(AF_NETLINK, SOCK_RAW, NM_NETLINK_GENERIC);
	if (sock < 0)
		return cached;

	uint8_t txbuf[64];
	memset(txbuf, 0, sizeof(txbuf));
	struct nlmsghdr *nlh = (struct nlmsghdr *)txbuf;
	struct nm_genlmsghdr *genl = (struct nm_genlmsghdr *)NLMSG_DATA(nlh);
	genl->cmd = NM_CTRL_CMD_GETFAMILY;
	size_t off = NLMSG_ALIGN(sizeof(*nlh)) + sizeof(*genl);
	off = nm_nl_put(txbuf, off, NM_CTRL_ATTR_FAMILY_NAME, "nl80211", 8);

	nlh->nlmsg_len   = (uint32_t)off;
	nlh->nlmsg_type  = NM_GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq   = 1;

	if (send(sock, txbuf, off, 0) < 0) {
		close(sock);
		return cached;
	}

	/* nl80211's CTRL_ATTR_OPS list alone runs into several KB on modern
	 * kernels; a too-small buffer here silently truncates the reply and
	 * makes NLMSG_OK() reject it (nlmsg_len then exceeds the bytes we
	 * actually received), so family resolution always failed. */
	uint8_t rxbuf[8192];
	ssize_t len = recv(sock, rxbuf, sizeof(rxbuf), 0);
	close(sock);
	if (len < (ssize_t)sizeof(struct nlmsghdr))
		return cached;

	struct nlmsghdr *rnlh = (struct nlmsghdr *)rxbuf;
	if (!NLMSG_OK(rnlh, (size_t)len) || rnlh->nlmsg_type == NLMSG_ERROR)
		return cached;

	struct rtattr *rta = (struct rtattr *)((char *)NLMSG_DATA(rnlh) + sizeof(struct nm_genlmsghdr));
	int rtl = (int)(rnlh->nlmsg_len - NLMSG_ALIGN(sizeof(*rnlh)) - sizeof(struct nm_genlmsghdr));
	for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
		if (rta->rta_type == NM_CTRL_ATTR_FAMILY_ID) {
			cached = *(uint16_t *)RTA_DATA(rta);
			break;
		}
	}
	return cached;
}

/* Current TX bitrate in bps via nl80211 GET_STATION; returns 0 when
 * unavailable. Used as a fallback for SIOCGIWRATE (see below), which some
 * 802.11n USB dongles (e.g. rt2800usb / RT2870-RT3070) get stuck reporting
 * a stale legacy OFDM floor rate once running at real HT rates. */
static int nm_get_wlan_bitrate_nl80211(const char *iface, const uint8_t mac[6])
{
	int family = nm_nl80211_family_id();
	if (family < 0)
		return 0;

	unsigned int ifindex = if_nametoindex(iface);
	if (!ifindex)
		return 0;

	int sock = socket(AF_NETLINK, SOCK_RAW, NM_NETLINK_GENERIC);
	if (sock < 0)
		return 0;

	uint8_t txbuf[128];
	memset(txbuf, 0, sizeof(txbuf));
	struct nlmsghdr *nlh = (struct nlmsghdr *)txbuf;
	struct nm_genlmsghdr *genl = (struct nm_genlmsghdr *)NLMSG_DATA(nlh);
	genl->cmd = NM_NL80211_CMD_GET_STATION;
	size_t off = NLMSG_ALIGN(sizeof(*nlh)) + sizeof(*genl);
	uint32_t ifidx32 = ifindex;
	off = nm_nl_put(txbuf, off, NM_NL80211_ATTR_IFINDEX, &ifidx32, sizeof(ifidx32));
	off = nm_nl_put(txbuf, off, NM_NL80211_ATTR_MAC, mac, 6);

	nlh->nlmsg_len   = (uint32_t)off;
	nlh->nlmsg_type  = (uint16_t)family;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq   = 1;

	if (send(sock, txbuf, off, 0) < 0) {
		close(sock);
		return 0;
	}

	uint8_t rxbuf[2048];
	ssize_t len = recv(sock, rxbuf, sizeof(rxbuf), 0);
	close(sock);
	if (len < (ssize_t)sizeof(struct nlmsghdr))
		return 0;

	struct nlmsghdr *rnlh = (struct nlmsghdr *)rxbuf;
	if (!NLMSG_OK(rnlh, (size_t)len) || rnlh->nlmsg_type == NLMSG_ERROR)
		return 0;

	struct rtattr *rta = (struct rtattr *)((char *)NLMSG_DATA(rnlh) + sizeof(struct nm_genlmsghdr));
	int rtl = (int)(rnlh->nlmsg_len - NLMSG_ALIGN(sizeof(*rnlh)) - sizeof(struct nm_genlmsghdr));
	int bps = 0;
	for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
		if (rta->rta_type != NM_NL80211_ATTR_STA_INFO)
			continue;
		struct rtattr *sinfo = (struct rtattr *)RTA_DATA(rta);
		int sinfo_len = (int)RTA_PAYLOAD(rta);
		for (; RTA_OK(sinfo, sinfo_len); sinfo = RTA_NEXT(sinfo, sinfo_len)) {
			if (sinfo->rta_type != NM_NL80211_STA_INFO_TX_BITRATE)
				continue;
			struct rtattr *rinfo = (struct rtattr *)RTA_DATA(sinfo);
			int rinfo_len = (int)RTA_PAYLOAD(sinfo);
			for (; RTA_OK(rinfo, rinfo_len); rinfo = RTA_NEXT(rinfo, rinfo_len)) {
				/* both units are 100 kbit/s */
				if (rinfo->rta_type == NM_NL80211_RATE_INFO_BITRATE32)
					bps = (int)(*(uint32_t *)RTA_DATA(rinfo) * 100000u);
				else if (rinfo->rta_type == NM_NL80211_RATE_INFO_BITRATE && bps == 0)
					bps = (int)(*(uint16_t *)RTA_DATA(rinfo) * 100000u);
			}
		}
	}
	return bps;
}

/* TX bitrate in bps via SIOCGIWRATE; returns 0 when not available.
 * Corrected with nl80211 GET_STATION when that reports a higher rate -
 * mac80211's WEXT compat layer can't represent HT/VHT rates and some
 * drivers just leave the field at a legacy floor instead of the real link
 * speed (see above), and that wrong value isn't reliably bounded by the
 * 802.11a/g 54 Mb/s ceiling on every driver, so nl80211 is always consulted
 * rather than only below some ioctl-value threshold. */
static int nm_get_wlan_bitrate(int sock, const char *iface)
{
	struct nm_iwreq wrq;
	memset(&wrq, 0, sizeof(wrq));
	strncpy(wrq.iw_ifname, iface, IFNAMSIZ - 1);
	int bps = 0;
	if (ioctl(sock, SIOCGIWRATE, &wrq) >= 0 && wrq.u.param.value > 0)
		bps = (int)wrq.u.param.value;

	char bssidbuf[18];
	if (nm_get_wlan_bssid(sock, iface, bssidbuf, sizeof(bssidbuf))) {
		uint8_t mac[6];
		if (sscanf(bssidbuf, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
		           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
			int nl_bps = nm_get_wlan_bitrate_nl80211(iface, mac);
			if (nl_bps > bps)
				bps = nl_bps;
		}
	}
	return bps;
}

/* Channel number from frequency in MHz */
static int nm_freq_to_channel(int mhz)
{
	if (mhz == 2484) return 14;
	if (mhz >= 2412 && mhz <= 2472) return (mhz - 2407) / 5;
	if (mhz >= 5180 && mhz <= 5980) return (mhz - 5000) / 5;
	if (mhz >= 5955 && mhz <= 7115) return (mhz - 5950) / 5;
	return 0;
}

/* Policy-routing table multihome setups keep per-adapter default routes in
 * (one entry per adapter, each with its own metric); see nm_scan_default_routes(). */
#define NM_MULTIHOME_RT_TABLE 201
#define NM_MAX_DEFAULT_ROUTES 16

struct nm_default_route {
	unsigned int ifindex;
	struct in_addr gw;
	unsigned int metric;
	int table;
};

/* Every interface's own default route (gateway + metric), plus which
 * interface currently owns the system's single active default gateway,
 * found via one NETLINK_ROUTE RTM_GETROUTE dump.
 *
 * Multihome setups keep one default route per interface in
 * NM_MULTIHOME_RT_TABLE, all of them present at the same time (so switching
 * is just a metric/ip-rule change) but only the one with the lowest metric
 * is actually used for outbound traffic. For a given interface, its
 * NM_MULTIHOME_RT_TABLE entry is authoritative when present; interfaces
 * without one (single-adapter, non-multihome devices) fall back to whatever
 * table their default route lives in (normally main). The winner is picked
 * the same way, but across interfaces: lowest metric among
 * NM_MULTIHOME_RT_TABLE entries if any exist, else lowest metric overall.
 *
 * Fills routes[] (up to max entries, one per interface that has a default
 * route) and returns the entry count. *out_winner_ifindex is set to the
 * winning interface's index, or 0 if no default route was found at all. */
static int nm_scan_default_routes(struct nm_default_route *routes, int max, unsigned int *out_winner_ifindex)
{
	int count = 0;
	*out_winner_ifindex = 0;

	int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) return 0;

	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
	} req;
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETROUTE;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq = 1;
	req.rtm.rtm_family = AF_INET;

	if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) { close(sock); return 0; }

	int done = 0;
	char buf[8192];

	while (!done) {
		ssize_t len = recv(sock, buf, sizeof(buf), 0);
		if (len <= 0) break;

		struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
		for (; NLMSG_OK(nlh, (size_t)len); nlh = NLMSG_NEXT(nlh, len)) {
			if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
				done = 1;
				break;
			}
			if (nlh->nlmsg_type != RTM_NEWROUTE) continue;

			struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);
			if (rtm->rtm_dst_len != 0) continue; /* default route only */

			struct rtattr *rta = RTM_RTA(rtm);
			int rtl = (int)RTM_PAYLOAD(nlh);
			unsigned int oif = 0, metric = 0;
			struct in_addr gw = { 0 };
			int haveGw = 0;

			for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
				switch (rta->rta_type) {
				case RTA_OIF:      oif = *(unsigned int *)RTA_DATA(rta); break;
				case RTA_GATEWAY:  gw = *(struct in_addr *)RTA_DATA(rta); haveGw = 1; break;
				case RTA_PRIORITY: metric = *(unsigned int *)RTA_DATA(rta); break;
				}
			}
			if (!haveGw || !oif) continue;

			/* keep, per interface, its NM_MULTIHOME_RT_TABLE entry if there is
			 * one, else the first entry seen for it */
			struct nm_default_route *existing = NULL;
			for (int i = 0; i < count; i++) {
				if (routes[i].ifindex == oif) { existing = &routes[i]; break; }
			}
			if (existing) {
				if (rtm->rtm_table == NM_MULTIHOME_RT_TABLE)
					*existing = (struct nm_default_route){ oif, gw, metric, rtm->rtm_table };
			} else if (count < max) {
				routes[count++] = (struct nm_default_route){ oif, gw, metric, rtm->rtm_table };
			}
		}
	}
	close(sock);

	/* winner: lowest metric among NM_MULTIHOME_RT_TABLE entries if any exist,
	 * else lowest metric overall */
	int anyMultihome = 0;
	for (int i = 0; i < count; i++)
		if (routes[i].table == NM_MULTIHOME_RT_TABLE) { anyMultihome = 1; break; }

	int winner = -1;
	for (int i = 0; i < count; i++) {
		if (anyMultihome && routes[i].table != NM_MULTIHOME_RT_TABLE) continue;
		if (winner < 0 || routes[i].metric < routes[winner].metric)
			winner = i;
	}
	if (winner >= 0) *out_winner_ifindex = routes[winner].ifindex;

	return count;
}

/* IPv6 addresses from /proc/net/if_inet6 as a JSON array.
 * out is set to "" when no addresses are found. */
/* IPv6 scope byte from /proc/net/if_inet6 -> human label, matches ifconfig's "Scope:" */
static const char *nm_ipv6_scope_str(int scope)
{
	switch (scope) {
	case 0x00: return "global";
	case 0x10: return "host";
	case 0x20: return "link";
	case 0x40: return "site";
	case 0x80: return "compat";
	default:   return "other";
	}
}

static void nm_get_ipv6(const char *iface, char *out, size_t outsz)
{
	out[0] = '\0';
	FILE *f = fopen("/proc/net/if_inet6", "r");
	if (!f) return;

	char line[256];
	int count = 0;
	size_t off = 1; /* reserve space for opening '[' */
	out[0] = '[';

	while (fgets(line, sizeof(line), f)) {
		char hex[33], name[IFNAMSIZ];
		int idx, plen, scope, flags;
		if (sscanf(line, "%32s %x %x %x %x %15s",
		           hex, &idx, &plen, &scope, &flags, name) != 6)
			continue;
		if (strcmp(name, iface) != 0) continue;

		struct in6_addr a;
		for (int i = 0; i < 16; i++) {
			char b[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
			a.s6_addr[i] = (uint8_t)strtoul(b, NULL, 16);
		}
		char astr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &a, astr, sizeof(astr));

		int n = snprintf(out + off, outsz - off,
		                 "%s{\"addr\":\"%s\",\"prefix\":%d,\"scope\":\"%s\"}",
		                 count ? "," : "", astr, plen, nm_ipv6_scope_str(scope));
		if (n > 0) off += n;
		count++;
	}
	fclose(f);
	if (count == 0) { out[0] = '\0'; return; }
	if (off < outsz) out[off++] = ']';
	out[off < outsz ? off : outsz - 1] = '\0';
}

/* WoL capability bitmask via ETHTOOL_GWOL; returns 0 if not supported/available */
static uint32_t nm_get_wol_supported(int sock, const char *iface)
{
	struct ifreq ifr;
	struct ethtool_wolinfo wol;
	memset(&ifr, 0, sizeof(ifr));
	memset(&wol, 0, sizeof(wol));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	wol.cmd = ETHTOOL_GWOL;
	ifr.ifr_data = (void *)&wol;
	if (ioctl(sock, SIOCETHTOOL, &ifr) < 0)
		return 0;
	return wol.supported;
}

/* Kernel module name from /sys/class/net/<iface>/device/driver[/module] symlink */
static void nm_get_driver(const char *iface, char *buf, size_t bufsz)
{
	char path[256];
	char link[256];
	ssize_t n;
	const char *slash;

	buf[0] = '\0';
	snprintf(path, sizeof(path), "/sys/class/net/%s/device/driver/module", iface);
	n = readlink(path, link, sizeof(link) - 1);
	if (n <= 0) {
		snprintf(path, sizeof(path), "/sys/class/net/%s/device/driver", iface);
		n = readlink(path, link, sizeof(link) - 1);
	}
	if (n > 0) {
		link[n] = '\0';
		slash = strrchr(link, '/');
		strncpy(buf, slash ? slash + 1 : link, bufsz - 1);
		buf[bufsz - 1] = '\0';
	}
}

/* Hardware ID: "VVVV:DDDD" (hex, no 0x prefix).
 * Tries PCI /sys/.../vendor+device first, then USB idVendor/idProduct. */
static void nm_get_hw_id(const char *iface, char *buf, size_t bufsz)
{
	char path[256];
	char tmp[16];
	FILE *f;
	char vendor[16] = {}, device[16] = {};

	buf[0] = '\0';

	/* PCI */
	snprintf(path, sizeof(path), "/sys/class/net/%s/device/vendor", iface);
	f = fopen(path, "r");
	if (f) {
		if (fgets(vendor, sizeof(vendor), f))
			vendor[strcspn(vendor, "\n\r")] = '\0';
		fclose(f);
	}
	snprintf(path, sizeof(path), "/sys/class/net/%s/device/device", iface);
	f = fopen(path, "r");
	if (f) {
		if (fgets(device, sizeof(device), f))
			device[strcspn(device, "\n\r")] = '\0';
		fclose(f);
	}
	if (vendor[0] && device[0]) {
		const char *v = strncmp(vendor, "0x", 2) == 0 ? vendor + 2 : vendor;
		const char *d = strncmp(device, "0x", 2) == 0 ? device + 2 : device;
		snprintf(buf, bufsz, "%s:%s", v, d);
		return;
	}

	/* USB: parent device has idVendor/idProduct */
	snprintf(path, sizeof(path), "/sys/class/net/%s/device/../idVendor", iface);
	f = fopen(path, "r");
	if (f) {
		if (fgets(tmp, sizeof(tmp), f)) {
			tmp[strcspn(tmp, "\n\r")] = '\0';
			strncpy(vendor, tmp, sizeof(vendor) - 1);
		}
		fclose(f);
	}
	snprintf(path, sizeof(path), "/sys/class/net/%s/device/../idProduct", iface);
	f = fopen(path, "r");
	if (f) {
		if (fgets(tmp, sizeof(tmp), f)) {
			tmp[strcspn(tmp, "\n\r")] = '\0';
			strncpy(device, tmp, sizeof(device) - 1);
		}
		fclose(f);
	}
	if (vendor[0] && device[0])
		snprintf(buf, bufsz, "%s:%s", vendor, device);
}

/* Physical bus the device hangs off ("usb", "pci", "platform", "sdio", ...)
 * from /sys/class/net/<iface>/device/subsystem symlink target. */
static void nm_get_bus(const char *iface, char *buf, size_t bufsz)
{
	char path[256];
	char link[256];
	ssize_t n;
	const char *slash;

	buf[0] = '\0';
	snprintf(path, sizeof(path), "/sys/class/net/%s/device/subsystem", iface);
	n = readlink(path, link, sizeof(link) - 1);
	if (n <= 0)
		return;
	link[n] = '\0';
	slash = strrchr(link, '/');
	strncpy(buf, slash ? slash + 1 : link, bufsz - 1);
	buf[bufsz - 1] = '\0';
}

/* Lines carrying these keys change on every scan (byte counters, timestamp)
 * and must not affect change detection, or every poll would look "changed". */
static int nm_line_is_volatile(const char *line, size_t len)
{
	static const char *const keys[] = { "\"rx_bytes\"", "\"tx_bytes\"", "\"updated\"", "\"bitrate_bps\"" };
	for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) {
		size_t klen = strlen(keys[k]);
		for (size_t i = 0; i + klen <= len; i++) {
			if (memcmp(line + i, keys[k], klen) == 0)
				return 1;
		}
	}
	return 0;
}

/* djb2 hash over buf, skipping volatile lines, to detect real state changes
 * across polls without being tripped up by ever-changing traffic counters. */
static unsigned long nm_content_hash(const char *s)
{
	unsigned long hash = 5381;
	const char *p = s;
	while (*p) {
		const char *nl = strchr(p, '\n');
		size_t len = nl ? (size_t)(nl - p) : strlen(p);
		if (!nm_line_is_volatile(p, len)) {
			hash = hash * 33 + len;
			for (size_t i = 0; i < len; i++)
				hash = hash * 33 + (unsigned char)p[i];
		}
		if (!nl)
			break;
		p = nl + 1;
	}
	return hash;
}

/* Returns 1 if the gathered state differs from the previous scan (ignoring
 * byte counters / timestamp), 0 otherwise. /var/run/netinfo is refreshed
 * either way so counters stay current for anyone reading the file directly.
 * Pass force=1 to always report "changed" (e.g. on client connect or a real
 * netlink/uevent event), bypassing the hash comparison. */
static int nm_gather_and_write(int force)
{
	static char buf[NETMON_BUF_SIZE];
	static unsigned long lastHash;
	static int haveHash;
	int off = 0;
	FILE *pf, *out;
	int sock;
	time_t t;
	struct tm *tm_val;
	char timebuf[32];
	char ipbuf[INET_ADDRSTRLEN];
	char macbuf[18];
	char ssid[NM_IW_ESSID_MAX + 1];
	char driverbuf[64];
	char hwidbuf[32];
	char busbuf[16];
	struct ifreq ifr;
	char line[256];
	int first = 1;

	time(&t);
	tm_val = gmtime(&t);
	if (tm_val)
		strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", tm_val);
	else
		strncpy(timebuf, "1970-01-01T00:00:00Z", sizeof(timebuf) - 1);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		LOG("netmon: socket: %s\n", strerror(errno));
		return 0;
	}

	pf = fopen("/proc/net/dev", "r");
	if (!pf) {
		LOG("netmon: cannot open /proc/net/dev: %s\n", strerror(errno));
		close(sock);
		return 0;
	}

	/* every interface's own default route (gw + metric) is reported below;
	 * the interface that owns the system's single active default gateway
	 * additionally gets "defgw": 1 (see nm_scan_default_routes()) */
	struct nm_default_route defRoutes[NM_MAX_DEFAULT_ROUTES];
	unsigned int defGwWinnerIfindex = 0;
	int defRouteCount = nm_scan_default_routes(defRoutes, NM_MAX_DEFAULT_ROUTES, &defGwWinnerIfindex);

	/* skip two header lines */
	if (!fgets(line, sizeof(line), pf) || !fgets(line, sizeof(line), pf)) {
		fclose(pf); close(sock); return 0;
	}

	off += snprintf(buf + off, sizeof(buf) - off,
		"{\n  \"updated\": \"%s\",\n  \"interfaces\": {\n", timebuf);

	while (fgets(line, sizeof(line), pf) && off < (int)sizeof(buf) - 300) {
		char *colon = strchr(line, ':');
		if (!colon) continue;
		*colon = '\0';
		char *iface = line;
		while (*iface == ' ' || *iface == '\t') iface++;
		if (strcmp(iface, "lo") == 0) continue;

		/* /proc/net/dev counters: rx_bytes is field 1, tx_bytes is field 9 */
		unsigned long long rxBytes = 0, txBytes = 0;
		sscanf(colon + 1, "%llu %*u %*u %*u %*u %*u %*u %*u %llu", &rxBytes, &txBytes);

		int wireless = nm_is_wireless(sock, iface);

		/* interface flags */
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
		int if_up = 0, if_running = 0, if_flags = 0;
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) >= 0) {
			if_flags   = ifr.ifr_flags;
			if_up      = (ifr.ifr_flags & IFF_UP)      != 0;
			if_running = (ifr.ifr_flags & IFF_RUNNING) != 0;
		}
		int vpn = !wireless && nm_is_vpn((short)if_flags, iface);

		/* MAC */
		macbuf[0] = '\0';
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
		if (ioctl(sock, SIOCGIFHWADDR, &ifr) >= 0) {
			unsigned char *m = (unsigned char *)ifr.ifr_hwaddr.sa_data;
			snprintf(macbuf, sizeof(macbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
				m[0], m[1], m[2], m[3], m[4], m[5]);
		}

		/* MTU */
		int mtu = -1;
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
		if (ioctl(sock, SIOCGIFMTU, &ifr) >= 0)
			mtu = ifr.ifr_mtu;

		/* IPv4 address + prefix + mask + broadcast + gateway */
		ipbuf[0] = '\0';
		char maskbuf[INET_ADDRSTRLEN] = {};
		char brdbuf[INET_ADDRSTRLEN] = {};
		char gwbuf[INET_ADDRSTRLEN] = {};
		unsigned int gwMetric = 0;
		int haveGwMetric = 0;
		int isDefGw = 0;
		int prefix = -1;
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
		if (ioctl(sock, SIOCGIFADDR, &ifr) >= 0) {
			inet_ntop(AF_INET,
				&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr,
				ipbuf, sizeof(ipbuf));
			memset(&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
			if (ioctl(sock, SIOCGIFNETMASK, &ifr) >= 0) {
				struct in_addr *nm_addr = &((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr;
				inet_ntop(AF_INET, nm_addr, maskbuf, sizeof(maskbuf));
				prefix = __builtin_popcount(ntohl(nm_addr->s_addr));
			}
			memset(&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
			if (ioctl(sock, SIOCGIFBRDADDR, &ifr) >= 0) {
				inet_ntop(AF_INET,
					&((struct sockaddr_in *)&ifr.ifr_broadaddr)->sin_addr,
					brdbuf, sizeof(brdbuf));
			}
			unsigned int ifindex = if_nametoindex(iface);
			for (int i = 0; i < defRouteCount; i++) {
				if (defRoutes[i].ifindex != ifindex) continue;
				gwMetric = defRoutes[i].metric;
				haveGwMetric = 1;
				inet_ntop(AF_INET, &defRoutes[i].gw, gwbuf, sizeof(gwbuf));
				isDefGw = (ifindex == defGwWinnerIfindex);
				break;
			}
		}

		/* IPv6 addresses */
		char ip6buf[512] = {};
		nm_get_ipv6(iface, ip6buf, sizeof(ip6buf));

		/* driver module name + hardware ID (PCI or USB) + bus */
		nm_get_driver(iface, driverbuf, sizeof(driverbuf));
		nm_get_hw_id(iface, hwidbuf, sizeof(hwidbuf));
		nm_get_bus(iface, busbuf, sizeof(busbuf));

		const char *iftype = wireless ? "wlan" : (vpn ? "vpn" : "lan");

		if (verbose)
			LOG("netmon: iface=%s type=%s up=%d running=%d mac=%s ip=%s/%d driver=%s hw=%s bus=%s\n",
				iface, iftype,
				if_up, if_running, macbuf,
				ipbuf[0] ? ipbuf : "-", prefix,
				driverbuf[0] ? driverbuf : "-",
				hwidbuf[0]   ? hwidbuf   : "-",
				busbuf[0]    ? busbuf    : "-");

		if (!first)
			off += snprintf(buf + off, sizeof(buf) - off, ",\n");
		first = 0;

		off += snprintf(buf + off, sizeof(buf) - off,
			"    \"%s\": {\n"
			"      \"type\": \"%s\",\n"
			"      \"up\": %s,\n"
			"      \"running\": %s,\n"
			"      \"mac\": \"%s\",\n"
			"      \"rx_bytes\": %llu,\n"
			"      \"tx_bytes\": %llu",
			iface,
			iftype,
			if_up      ? "true" : "false",
			if_running ? "true" : "false",
			macbuf,
			rxBytes,
			txBytes);

		if (mtu >= 0)
			off += snprintf(buf + off, sizeof(buf) - off,
				",\n      \"mtu\": %d", mtu);

		if (ipbuf[0]) {
			off += snprintf(buf + off, sizeof(buf) - off,
				",\n      \"ip4\": \"%s\"", ipbuf);
			if (maskbuf[0])
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"mask\": \"%s\"", maskbuf);
			if (prefix >= 0)
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"prefix4\": %d", prefix);
			if (brdbuf[0])
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"brd\": \"%s\"", brdbuf);
			if (gwbuf[0])
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"gw\": \"%s\"", gwbuf);
			if (haveGwMetric)
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"metric\": %u", gwMetric);
			if (isDefGw)
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"defgw\": 1");
		}
		if (ip6buf[0])
			off += snprintf(buf + off, sizeof(buf) - off,
				",\n      \"ip6\": %s", ip6buf);

		if (wireless) {
			ssid[0] = '\0';
			nm_get_wlan_ssid(sock, iface, ssid, sizeof(ssid));
			char bssidbuf[18] = {};
			int bssid_ok = if_running ? nm_get_wlan_bssid(sock, iface, bssidbuf, sizeof(bssidbuf)) : 0;
			int freq_mhz = if_running ? nm_get_wlan_freq_mhz(sock, iface) : 0;
			int bitrate  = if_running ? nm_get_wlan_bitrate(sock, iface) : 0;
			int sig      = if_running ? nm_get_wlan_signal(sock, iface) : 0;

			off += snprintf(buf + off, sizeof(buf) - off,
				",\n      \"link\": %s", if_running ? "true" : "false");
			off += snprintf(buf + off, sizeof(buf) - off,
				",\n      \"ssid\": \"");
			for (char *p = ssid; *p && off + 4 < (int)sizeof(buf); p++) {
				if (*p == '"' || *p == '\\')
					buf[off++] = '\\';
				if ((unsigned char)*p >= 0x20)
					buf[off++] = *p;
			}
			off += snprintf(buf + off, sizeof(buf) - off, "\"");
			if (bssid_ok)
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"bssid\": \"%s\"", bssidbuf);
			if (freq_mhz > 0) {
				int ch = nm_freq_to_channel(freq_mhz);
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"freq_mhz\": %d", freq_mhz);
				if (ch > 0)
					off += snprintf(buf + off, sizeof(buf) - off,
						",\n      \"channel\": %d", ch);
			}
			if (bitrate > 0)
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"bitrate_bps\": %d", bitrate);
			if (sig != 0)
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"signal_dbm\": %d", sig);
			if (verbose)
				LOG("netmon:   wlan link=%d ssid='%s' bssid=%s freq=%d ch=%d rate=%d sig=%d\n",
					if_running, ssid, bssidbuf,
					freq_mhz, nm_freq_to_channel(freq_mhz), bitrate, sig);
		} else {
			int link = nm_get_link(sock, iface);
			int speed = -1, duplex = -1, port = -1, xcvr = -1, autoneg = -1;
			uint32_t supported = 0;
			nm_get_eth_info(sock, iface, &speed, &duplex, &port, &xcvr, &autoneg, &supported);

			off += snprintf(buf + off, sizeof(buf) - off,
				",\n      \"link\": %s", link > 0 ? "true" : "false");
			if (speed > 0)
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"speed\": %d", speed);
			if (duplex >= 0)
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"duplex\": \"%s\"", duplex == 1 ? "full" : "half");
			const char *port_s = (port >= 0) ? nm_port_str((uint8_t)port) : NULL;
			if (port_s)
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"port\": \"%s\"", port_s);
			if (xcvr == 0)
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"transceiver\": \"internal\"");
			else if (xcvr == 1)
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"transceiver\": \"external\"");
			if (autoneg >= 0)
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"autoneg\": %s", autoneg ? "true" : "false");
			uint32_t wol = nm_get_wol_supported(sock, iface);
			if (wol)
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"wol_supported\": %u", wol);
			if (supported)
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"link_supported\": %u", supported);
			if (verbose)
				LOG("netmon:   lan  link=%d speed=%d duplex=%s port=%s xcvr=%d autoneg=%d wol=0x%x supported=0x%x\n",
					link, speed,
					duplex == 1 ? "full" : duplex == 0 ? "half" : "?",
					port_s ? port_s : "?", xcvr, autoneg, wol, supported);
		}

		if (driverbuf[0])
			off += snprintf(buf + off, sizeof(buf) - off,
				",\n      \"driver\": \"%s\"", driverbuf);
		if (hwidbuf[0])
			off += snprintf(buf + off, sizeof(buf) - off,
				",\n      \"hw_id\": \"%s\"", hwidbuf);
		if (busbuf[0])
			off += snprintf(buf + off, sizeof(buf) - off,
				",\n      \"bus\": \"%s\"", busbuf);

		off += snprintf(buf + off, sizeof(buf) - off, "\n    }");
	}
	fclose(pf);
	close(sock);

	off += snprintf(buf + off, sizeof(buf) - off, "\n  }\n}\n");

	out = fopen(NETINFO_TMP, "w");
	if (out) {
		fputs(buf, out);
		fclose(out);
		rename(NETINFO_TMP, NETINFO_PATH);
		if (verbose)
			LOG("netmon: wrote %s (%d bytes)\n", NETINFO_PATH, off);
	} else {
		LOG("netmon: cannot write %s: %s\n", NETINFO_TMP, strerror(errno));
	}

	unsigned long hash = nm_content_hash(buf);
	int changed = force || !haveHash || hash != lastHash;
	lastHash = hash;
	haveHash = 1;
	return changed;
}

/* ============================================================
 * Event push socket + event building
 * ============================================================ */

static int nm_setup_event_server(void)
{
	struct sockaddr_un sa;
	int srv;
	unlink(NET_SOCKET_NAME);
	srv = socket(AF_UNIX, SOCK_STREAM, 0);
	if (srv < 0) { LOG("netmon: event socket: %s\n", strerror(errno)); return -1; }
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, NET_SOCKET_NAME, sizeof(sa.sun_path) - 1);
	if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		LOG("netmon: event bind: %s\n", strerror(errno));
		close(srv); return -1;
	}
	chmod(NET_SOCKET_NAME, 0600);
	listen(srv, 1);
	if (verbose) LOG("netmon: event socket ready: %s\n", NET_SOCKET_NAME);
	return srv;
}

/* Send msg to client; closes and returns -1 on error. */
static int nm_send_to_client(int cli, const char *msg, size_t len)
{
	if (cli < 0) return cli;
	if (send(cli, msg, len, MSG_NOSIGNAL) < 0) {
		if (verbose) LOG("netmon: client disconnected\n");
		close(cli);
		return -1;
	}
	return cli;
}

/* Append a formatted event line to evtbuf; returns new offset. */
static int nm_evt(char *evtbuf, int off, int max, const char *fmt, ...)
{
	va_list ap;
	int n;
	if (off >= max - 1) return off;
	va_start(ap, fmt);
	n = vsnprintf(evtbuf + off, max - off, fmt, ap);
	va_end(ap);
	return (n > 0 && off + n < max) ? off + n : off;
}

/* ============================================================
 * NETLINK_ROUTE parser → structured event lines
 * ============================================================ */

static int nm_handle_rtnetlink(int nls, char *evtbuf, int evtmax)
{
	char buf[8192];
	ssize_t len = recv(nls, buf, sizeof(buf), MSG_DONTWAIT);
	if (len <= 0) return 0;

	int off = 0;
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

	for (; NLMSG_OK(nlh, (unsigned int)len); nlh = NLMSG_NEXT(nlh, len)) {
		if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR)
			break;

		if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK) {
			struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
			char ifname[IFNAMSIZ] = {0};
			if_indextoname(ifi->ifi_index, ifname);
			if (!ifname[0] || strcmp(ifname, "lo") == 0) continue;

			if (nlh->nlmsg_type == RTM_DELLINK) {
				if (verbose) LOG("netmon: RTM_DELLINK %s\n", ifname);
				off = nm_evt(evtbuf, off, evtmax, "IFACE_REMOVE,%s\n", ifname);
			} else {
				/* up: administrative state (ifconfig up/down), matches the
				 * "up" field in the full JSON scan / adapter.kernelUp.
				 * running: carrier/association state (cable present resp.
				 * associated to an AP), matches "running"/adapter.kernelLink.
				 * These are independent — WLAN stays running=0 until
				 * associated regardless of admin state. */
				int up = (ifi->ifi_flags & IFF_UP) != 0;
				int running = (ifi->ifi_flags & IFF_RUNNING) != 0;
				if (verbose) LOG("netmon: RTM_NEWLINK %s up=%d running=%d\n", ifname, up, running);
				off = nm_evt(evtbuf, off, evtmax, "LINK,%s,%s,%s\n", ifname,
					up ? "up" : "down", running ? "up" : "down");
				if (up) {
					int s = socket(AF_INET, SOCK_DGRAM, 0);
					if (s >= 0) {
						if (nm_is_wireless(s, ifname))
							off = nm_evt(evtbuf, off, evtmax, "SCAN_TRIGGER,%s\n", ifname);
						close(s);
					}
				}
			}
		}
		else if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR) {
			struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
			if (ifa->ifa_family != AF_INET) continue;

			char ifname[IFNAMSIZ] = {0};
			if_indextoname(ifa->ifa_index, ifname);
			if (!ifname[0] || strcmp(ifname, "lo") == 0) continue;

			char ipbuf[INET_ADDRSTRLEN] = {0};
			int rtalen = IFA_PAYLOAD(nlh);
			struct rtattr *rta;
			for (rta = IFA_RTA(ifa); RTA_OK(rta, rtalen); rta = RTA_NEXT(rta, rtalen)) {
				if (rta->rta_type == IFA_LOCAL) {
					inet_ntop(AF_INET, RTA_DATA(rta), ipbuf, sizeof(ipbuf));
					break;
				}
			}
			if (verbose) LOG("netmon: RTM_%sADDR %s %s/%d\n",
				nlh->nlmsg_type == RTM_NEWADDR ? "NEW" : "DEL",
				ifname, ipbuf, ifa->ifa_prefixlen);
			off = nm_evt(evtbuf, off, evtmax, "IP,%s,%s/%d\n",
				ifname, ipbuf, ifa->ifa_prefixlen);
		}
	}
	return off;
}

/* ============================================================
 * NETLINK_KOBJECT_UEVENT parser → IFACE_ADD / IFACE_REMOVE
 * ============================================================ */

static int nm_handle_uevent(int uev_sock, char *evtbuf, int evtmax)
{
	char buf[4096];
	ssize_t len = recv(uev_sock, buf, sizeof(buf) - 1, MSG_DONTWAIT);
	if (len <= 0) return 0;
	buf[len] = '\0';

	char action[32] = {0}, subsystem[32] = {0}, iface[IFNAMSIZ] = {0};
	char *p = buf, *end = buf + len, *eq;

	/* skip binary libudev header if present (udevd re-broadcast) */
	if (len > 7 && !strncmp(p, "libudev", 7)) {
		while (p < end && *p) p++;
		if (p < end) p++;
	} else {
		/* raw kernel uevent: first string is "ACTION@devpath" */
		char *at = (char *)memchr(p, '@', end - p);
		if (at) {
			size_t al = (size_t)(at - p) < sizeof(action) - 1
				? (size_t)(at - p) : sizeof(action) - 1;
			memcpy(action, p, al);
		}
		while (p < end && *p) p++;
		if (p < end) p++;
	}

	while (p < end) {
		if (!*p) { p++; continue; }
		eq = (char *)memchr(p, '=', end - p);
		if (!eq) { while (p < end && *p) p++; if (p < end) p++; continue; }
		*eq = '\0';
		if (!strcmp(p, "ACTION")    && !action[0])    strncpy(action,    eq + 1, sizeof(action)    - 1);
		else if (!strcmp(p, "SUBSYSTEM"))              strncpy(subsystem, eq + 1, sizeof(subsystem) - 1);
		else if (!strcmp(p, "INTERFACE"))              strncpy(iface,     eq + 1, sizeof(iface)     - 1);
		*eq = '=';
		while (p < end && *p) p++;
		if (p < end) p++;
	}

	if (strcmp(subsystem, "net") != 0 || !iface[0] || strcmp(iface, "lo") == 0)
		return 0;

	int off = 0;
	if (!strcmp(action, "add")) {
		if (verbose) LOG("netmon: uevent IFACE_ADD %s\n", iface);
		off = nm_evt(evtbuf, off, evtmax, "IFACE_ADD,%s\n", iface);
	} else if (!strcmp(action, "remove")) {
		if (verbose) LOG("netmon: uevent IFACE_REMOVE %s\n", iface);
		off = nm_evt(evtbuf, off, evtmax, "IFACE_REMOVE,%s\n", iface);
	}
	return off;
}

/* ============================================================
 * Network monitor thread
 * ============================================================ */

static void *monitor_thread(void *arg)
{
	int nls = -1, uev_sock = -1, net_srv = -1, net_cli = -1;
	struct sockaddr_nl sa;
	(void)arg;

	if (verbose) LOG("netmon: thread started\n");

	/* NETLINK_ROUTE: link-state and IP-address events */
	nls = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nls < 0) { LOG("netmon: netlink socket: %s\n", strerror(errno)); goto out; }
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
	if (bind(nls, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		LOG("netmon: netlink bind: %s\n", strerror(errno)); goto out;
	}

	/* NETLINK_KOBJECT_UEVENT: interface add / remove (e.g. USB WLAN stick) */
	uev_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if (uev_sock >= 0) {
		struct sockaddr_nl unl;
		memset(&unl, 0, sizeof(unl));
		unl.nl_family = AF_NETLINK;
		unl.nl_groups = 0xFFFFFFFF;
		if (bind(uev_sock, (struct sockaddr *)&unl, sizeof(unl)) < 0) {
			LOG("netmon: uevent bind: %s\n", strerror(errno));
			close(uev_sock); uev_sock = -1;
		}
	} else {
		LOG("netmon: uevent socket: %s\n", strerror(errno));
	}

	/* AF_UNIX SOCK_STREAM push socket for NetworkManager */
	net_srv = nm_setup_event_server();

	nm_gather_and_write(1); /* initial scan */

	/* unattended SMB/NFS discovery (see NETSCAN block below) - own thread,
	 * since its "wait for an IP" step can block indefinitely and must not
	 * hold up this thread's own event loop below */
	pthread_t autoscanTid;
	if (pthread_create(&autoscanTid, NULL, nm_autoscan_thread, NULL) == 0)
		pthread_detach(autoscanTid);
	else if (verbose)
		LOG("netscan: autoscan thread create failed: %s\n", strerror(errno));

	while (running) {
		fd_set fds;
		struct timeval tv;
		int nfds = 0, r;
		char evtbuf[512];
		int evtlen = 0;

#define ADDFD(fd) do { if ((fd) >= 0) { FD_SET((fd), &fds); if ((fd) >= nfds) nfds = (fd) + 1; } } while (0)
		FD_ZERO(&fds);
		ADDFD(nls);
		ADDFD(uev_sock);
		ADDFD(g_stop_pipe[0]);
		ADDFD(net_srv);
		ADDFD(net_cli);
#undef ADDFD

		tv.tv_sec = POLL_INTERVAL_SEC; tv.tv_usec = 0;
		r = select(nfds, &fds, NULL, NULL, &tv);

		if (!running) break;
		if (r < 0) { if (errno == EINTR) continue; break; }
		if (g_stop_pipe[0] >= 0 && FD_ISSET(g_stop_pipe[0], &fds)) break;

		/* accept new NetworkManager client (replaces any existing one) */
		if (net_srv >= 0 && FD_ISSET(net_srv, &fds)) {
			int nc = accept(net_srv, NULL, NULL);
			if (nc >= 0) {
				if (net_cli >= 0) close(net_cli);
				net_cli = nc;
				if (verbose) LOG("netmon: client connected\n");
				/* force a fresh scan and send current state immediately */
				nm_gather_and_write(1);
				net_cli = nm_send_to_client(net_cli, "UPDATE\n", 7);
			}
		}

		/* detect client disconnect (data / EOF on client fd) */
		if (net_cli >= 0 && FD_ISSET(net_cli, &fds)) {
			char tmp[8];
			if (recv(net_cli, tmp, sizeof(tmp), MSG_DONTWAIT) <= 0) {
				if (verbose) LOG("netmon: client disconnected\n");
				close(net_cli); net_cli = -1;
			}
		}

		/* NETLINK_ROUTE events → parse to specific event lines */
		if (nls >= 0 && FD_ISSET(nls, &fds))
			evtlen += nm_handle_rtnetlink(nls, evtbuf + evtlen, (int)sizeof(evtbuf) - evtlen);

		/* KOBJECT_UEVENT → IFACE_ADD / IFACE_REMOVE */
		if (uev_sock >= 0 && FD_ISSET(uev_sock, &fds))
			evtlen += nm_handle_uevent(uev_sock, evtbuf + evtlen, (int)sizeof(evtbuf) - evtlen);

		if (evtlen > 0) {
			/* specific events: gather first so /var/run/netinfo is fresh.
			 * Also push UPDATE so the client does a full resync — the
			 * specific event handlers (LINK/IP/...) only touch a few
			 * fields, not everything nm_gather_and_write() just refreshed. */
			nm_gather_and_write(1);
			net_cli = nm_send_to_client(net_cli, evtbuf, evtlen);
			net_cli = nm_send_to_client(net_cli, "UPDATE\n", 7);
		} else if (r == 0) {
			/* fallback poll timeout */
			if (verbose) LOG("netmon: poll timeout – refreshing\n");
			if (nm_gather_and_write(0)) {
				net_cli = nm_send_to_client(net_cli, "UPDATE\n", 7);
			} else if (verbose) {
				LOG("netmon: poll timeout – no change, skipping notify\n");
			}
		}
	}

out:
	if (net_cli >= 0) close(net_cli);
	if (net_srv >= 0) { close(net_srv); unlink(NET_SOCKET_NAME); }
	if (uev_sock >= 0) close(uev_sock);
	if (nls >= 0) close(nls);
	if (verbose) LOG("netmon: thread stopped\n");
	return NULL;
}

int main(int argc, char **argv)
{

	int sock, msgsock, rval;
	struct sockaddr_un server;
	char buf[256];
	int c = 0;

	log_stream = stdout;

	struct sigaction sa;
	sa.sa_handler = handle_signal;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0; /* no SA_RESTART: let accept() return EINTR */
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	while ((c = getopt(argc, argv, "v")) != -1)
	{
		if (c == 'v')
			verbose = 1;
	}

	if (unlink(CMD_SOCKET_NAME) == -1 && errno != ENOENT)
	{
		perror("delete server socket");
		exit(1);
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
	{
		perror("opening stream socket");
		exit(1);
	}
	server.sun_family = AF_UNIX;
	strncpy(server.sun_path, CMD_SOCKET_NAME, sizeof(server.sun_path) - 1);
	server.sun_path[sizeof(server.sun_path) - 1] = '\0';
	if (bind(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_un)))
	{
		perror("binding stream socket");
		exit(1);
	}
	chmod(CMD_SOCKET_NAME, 0600);

	LOG("Start\n");

	if (pipe(g_stop_pipe) < 0)
		LOG("stop pipe: %s\n", strerror(errno));

	if (pthread_create(&g_monitor_tid, NULL, monitor_thread, NULL) != 0)
		LOG("netmon: pthread_create failed: %s\n", strerror(errno));

	listen(sock, 5);
	while (running)
	{
		msgsock = accept(sock, 0, 0);
		if (msgsock == -1)
		{
			if (errno == EINTR)
				break;
			perror("accept");
		}
		else
		{
			do
			{
				memset(buf, 0, sizeof(buf));
				if ((rval = read(msgsock, buf, sizeof(buf) - 1)) < 0)
				{
					perror("reading stream message");
				}
				else
				{
					if (strlen(buf) > 0)
					{
						if (verbose)
							LOG("processMessage %zu --> '%s' \n", strlen(buf), buf);

						if (strncmp(buf, "ACTION ", 7) == 0)
						{
							/* New line-based protocol:
							 * Client sends: "ACTION <id> <TYPE> [<data>]\n"
							 * Daemon replies: "DONE <id> <exitcode>\n"
							 *              or "ERROR <id> <exitcode>\n"
							 */
							char *p = buf + 7;
							unsigned long reqId = strtoul(p, &p, 10);
							while (*p == ' ') p++;
							/* extract action type (up to next space or newline) */
							char ntype[32] = {};
							size_t ti = 0;
							while (*p && *p != ' ' && *p != '\n' && *p != '\r' && ti < sizeof(ntype) - 1)
								ntype[ti++] = *p++;
							while (*p == ' ') p++;
							/* rest of line is data; strip trailing newline */
							size_t dlen = strlen(p);
							while (dlen > 0 && (p[dlen - 1] == '\n' || p[dlen - 1] == '\r'))
								p[--dlen] = '\0';
							/* reconstruct as "TYPE,data" or "TYPE" for processMessage */
							char msg[300];
							if (dlen > 0)
								snprintf(msg, sizeof(msg), "%s,%s", ntype, p);
							else
								strncpy(msg, ntype, sizeof(msg) - 1);
							int rc = processMessage(msg);
							int exitcode;
							if (rc < 0)
								exitcode = 127;
							else if (WIFEXITED(rc))
								exitcode = WEXITSTATUS(rc);
							else
								exitcode = 1;
							char reply[64];
							snprintf(reply, sizeof(reply),
							         exitcode == 0 ? "DONE %lu %d\n" : "ERROR %lu %d\n",
							         reqId, exitcode);
							ssize_t wr = send(msgsock, reply, strlen(reply), MSG_NOSIGNAL);
							if (verbose)
								LOG("write %s --> %zd\n", reply, wr);
						}
						else
						{
							/* Legacy null-terminated protocol: "COMMAND,data\0" → "RC:<n>" */
							int rc = processMessage(buf);
							char reply[16];
							int exitcode;
							if (rc < 0)
								exitcode = 127;
							else if (WIFEXITED(rc))
								exitcode = WEXITSTATUS(rc);
							else
								exitcode = 1;
							snprintf(reply, sizeof(reply), "RC:%d", exitcode);
							ssize_t wr = send(msgsock, reply, strlen(reply), MSG_NOSIGNAL);
							if (verbose)
								LOG("write %s --> %zd\n", reply, wr);
						}
					}
				}
			} while (rval > 0);
			close(msgsock);
		}
	}
	close(sock);
	unlink(CMD_SOCKET_NAME);

	pthread_join(g_monitor_tid, NULL);

	if (g_stop_pipe[0] >= 0) close(g_stop_pipe[0]);
	if (g_stop_pipe[1] >= 0) close(g_stop_pipe[1]);

	LOG("END\n");

	return EXIT_SUCCESS;
}

static unsigned short icmpChecksum(const void *buf, int len)
{
	const unsigned short *p = buf;
	unsigned int sum = 0;
	while (len > 1) {
		sum += *p++;
		len -= 2;
	}
	if (len == 1)
		sum += *(const unsigned char *)p;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)~sum;
}

/* One ICMP echo request bound to iface, waits up to timeoutMs for a matching
 * reply. Returns 0 if a reply was received, 1 otherwise. host may be a
 * dotted-quad or a hostname (resolved via getaddrinfo). */
static int doPing(const char *iface, const char *host, int timeoutMs)
{
	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res)
		return 1;
	struct sockaddr_in dst = *(struct sockaddr_in *)res->ai_addr;
	freeaddrinfo(res);

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0)
		return 1;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
		close(sock);
		return 1;
	}

	unsigned short pid = (unsigned short)(getpid() & 0xFFFF);
	struct __attribute__((packed)) {
		unsigned char type, code;
		unsigned short checksum, id, seq;
		char payload[5];
	} pkt;
	pkt.type = 8;
	pkt.code = 0;
	pkt.checksum = 0;
	pkt.id = htons(pid);
	pkt.seq = htons(1);
	memcpy(pkt.payload, "e2net", 5);
	pkt.checksum = icmpChecksum(&pkt, sizeof(pkt));

	dst.sin_port = 0;
	if (sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		close(sock);
		return 1;
	}

	struct timespec deadline;
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += timeoutMs / 1000;
	deadline.tv_nsec += (long)(timeoutMs % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000L;
	}

	int result = 1;
	unsigned char buf[1024];
	for (;;) {
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		long remainMs = (deadline.tv_sec - now.tv_sec) * 1000 + (deadline.tv_nsec - now.tv_nsec) / 1000000L;
		if (remainMs <= 0)
			break;
		struct timeval tv;
		tv.tv_sec = remainMs / 1000;
		tv.tv_usec = (remainMs % 1000) * 1000;
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

		ssize_t n = recv(sock, buf, sizeof(buf), 0);
		if (n < 20)
			continue;
		int ihl = (buf[0] & 0x0F) * 4;
		if (n < ihl + 8)
			continue;
		unsigned char rtype = buf[ihl];
		unsigned short rid;
		memcpy(&rid, buf + ihl + 4, 2);
		rid = ntohs(rid);
		if (rtype == 0 && rid == pid) {
			result = 0;
			break;
		}
	}
	close(sock);
	return result;
}

/* Resolve host via getaddrinfo (AF_INET). Returns 0 if resolved, 1 otherwise. */
static int doResolve(const char *host)
{
	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	int rc = getaddrinfo(host, NULL, &hints, &res);
	if (res)
		freeaddrinfo(res);
	return (rc == 0) ? 0 : 1;
}

/* ============================================================
 * NETSCAN – active TCP connect-scan for host/service discovery. Replaces
 * the earlier passive ARP/NDP neighbor-table snapshot approach, which only
 * ever listed hosts this box had already exchanged link-layer traffic
 * with - close to empty on a quiet LAN. This actively probes every host
 * address in a given range against a small port list and writes the
 * result to /var/run/netscan.
 *
 * Two callers, both serialized via g_netscan_mutex (see declaration
 * above) since they'd otherwise race on the static result/DNS-cache
 * buffers below:
 *   - CMD_NETSCAN (processMessage() below) - caller-specified range/ports,
 *     runs synchronously like every other command in this file (blocks the
 *     requesting client for the scan's duration, same as doPing()'s 2s
 *     block - fine since the scan itself is bounded, see below).
 *   - nm_run_autoscan() - unattended, fixed SMB/NFS ports, run twice 3s
 *     apart once at monitor_thread() startup, in that thread (so it never
 *     blocks the daemon.socket accept loop, which lives in main()).
 *
 * Non-blocking connect()+poll() in fixed-size batches keeps the scan
 * itself bounded by NETSCAN_TIMEOUT_MS per batch, not per host - a
 * dead/unused IP (no ARP reply, connect() would otherwise hang) costs no
 * more than any live one, so a full /24 across a handful of ports finishes
 * in low single-digit seconds worst case even against an all-dead subnet.
 *
 * Each unique open host is additionally reverse-DNS-resolved (PTR query).
 * This is a minimal hand-rolled UDP DNS client, not getnameinfo()/
 * gethostbyaddr(): those block on the system resolver with no
 * caller-controllable timeout (several seconds per host on an unreachable
 * or non-responding nameserver), which would defeat the point of bounding
 * the scan at all. Bounded by DNS_TIMEOUT_MS via poll(), one nameserver
 * (the first one in /etc/resolv.conf), one UDP datagram, one wait, no
 * retries.
 * ============================================================ */

#define NETSCAN_PATH        "/var/run/netscan"
#define NETSCAN_TMP         "/var/run/netscan.tmp"
#define NETSCAN_MAX_HOSTS   256   /* caller must chunk anything bigger than a /24 */
#define NETSCAN_MAX_PORTS   8
#define NETSCAN_BATCH       256   /* concurrent in-flight connects */
#define NETSCAN_TIMEOUT_MS  400   /* per batch, not per host */
#define NETSCAN_MAX_OPEN    256   /* result buffer cap */
#define DNS_TIMEOUT_MS      300   /* per host, reverse PTR lookup */
#define DNS_NAME_MAX        256

typedef struct {
	uint32_t ip;   /* host order */
	uint16_t port;
	int fd;
} nm_scan_slot_t;

typedef struct {
	uint32_t ip;   /* host order */
	uint16_t port;
} nm_scan_open_t;

/* Polls up to n in-flight non-blocking connects to completion or
 * NETSCAN_TIMEOUT_MS, whichever comes first; appends successes to
 * open[]/*openCount and closes every fd before returning. */
static void nm_scan_run_batch(nm_scan_slot_t *slots, int n,
	nm_scan_open_t *open, int *openCount, int openMax)
{
	struct pollfd pfds[NETSCAN_BATCH];
	for (int i = 0; i < n; i++) {
		pfds[i].fd = slots[i].fd;
		pfds[i].events = POLLOUT;
		pfds[i].revents = 0;
	}

	struct timespec deadline;
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += NETSCAN_TIMEOUT_MS / 1000;
	deadline.tv_nsec += (long)(NETSCAN_TIMEOUT_MS % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000L; }

	int remaining = n;
	while (remaining > 0) {
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		long remainMs = (deadline.tv_sec - now.tv_sec) * 1000 +
			(deadline.tv_nsec - now.tv_nsec) / 1000000L;
		if (remainMs <= 0)
			break;

		if (poll(pfds, n, (int)remainMs) <= 0)
			break;

		for (int i = 0; i < n; i++) {
			if (pfds[i].fd < 0 || pfds[i].revents == 0)
				continue;
			int err = 0;
			socklen_t elen = sizeof(err);
			getsockopt(pfds[i].fd, SOL_SOCKET, SO_ERROR, &err, &elen);
			if (err == 0 && *openCount < openMax) {
				open[*openCount].ip = slots[i].ip;
				open[*openCount].port = slots[i].port;
				(*openCount)++;
			}
			close(pfds[i].fd);
			pfds[i].fd = -1;
			remaining--;
		}
	}

	for (int i = 0; i < n; i++) {
		if (pfds[i].fd >= 0)
			close(pfds[i].fd);
	}
}

/* Decodes a (possibly compressed) DNS name starting at pkt[offset] into
 * out (dot-separated, NUL-terminated). Returns the number of bytes the
 * name occupied in the original stream starting at offset (2 if it was
 * just a compression pointer), or -1 on a malformed/out-of-bounds name. */
static int nm_dns_read_name(const unsigned char *pkt, int pktlen, int offset, char *out, int outsz)
{
	int outlen = 0;
	int pos = offset;
	int consumed = -1;
	int jumps = 0;

	while (pos < pktlen) {
		int len = pkt[pos];
		if (len == 0) {
			pos++;
			if (consumed < 0) consumed = pos - offset;
			break;
		}
		if ((len & 0xC0) == 0xC0) {
			if (pos + 1 >= pktlen) return -1;
			if (consumed < 0) consumed = pos - offset + 2;
			if (++jumps > 20) return -1; /* guard against pointer loops */
			pos = ((len & 0x3F) << 8) | pkt[pos + 1];
			continue;
		}
		pos++;
		if (pos + len > pktlen || outlen + len + 1 >= outsz)
			return -1;
		if (outlen > 0)
			out[outlen++] = '.';
		memcpy(out + outlen, pkt + pos, len);
		outlen += len;
		pos += len;
	}
	out[outlen] = '\0';
	return consumed;
}

/* A PTR response can come from any nameserver reachable on the LAN,
 * including a spoofed/malicious one - the name it returns is untrusted
 * input that ends up embedded verbatim in a JSON file. Replace anything
 * outside the standard hostname charset so it can't be broken/injected
 * into by a crafted reply. */
static void nm_sanitize_hostname(char *s)
{
	for (; *s; s++) {
		char c = *s;
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'))
			*s = '_';
	}
}

/* RFC1918 addresses have no real public reverse delegation, yet many ISP
 * resolvers answer any unknown PTR query with a synthesized name instead of
 * NXDOMAIN - typically "<ip-with-dashes>.<something>.<isp-domain>", e.g.
 * "192-168-2-102.r.airtelkenya.com" for 192.168.2.102. Treat a PTR result
 * that literally embeds the queried IP (dotted octets, dash-joined, either
 * order) as such a catch-all rather than a real local hostname. */
static int nm_looks_like_isp_wildcard(const char *name, uint32_t ip)
{
	unsigned a = (ip >> 24) & 0xFF, b = (ip >> 16) & 0xFF, c = (ip >> 8) & 0xFF, d = ip & 0xFF;
	char forward[20], reversed[20];
	snprintf(forward, sizeof(forward), "%u-%u-%u-%u", a, b, c, d);
	snprintf(reversed, sizeof(reversed), "%u-%u-%u-%u", d, c, b, a);
	return strstr(name, forward) != NULL || strstr(name, reversed) != NULL;
}

/* Reverse-resolves ip (host order) to a hostname via a single PTR query to
 * the first nameserver in /etc/resolv.conf, bounded by DNS_TIMEOUT_MS.
 * Leaves out[0] = '\0' on any failure/timeout/missing resolv.conf. */
static void nm_dns_reverse_lookup(uint32_t ip, char *out, size_t outsz)
{
	out[0] = '\0';

	char nsIp[64] = {0};
	FILE *f = fopen("/etc/resolv.conf", "r");
	if (!f)
		return;
	char line[256];
	while (fgets(line, sizeof(line), f)) {
		char probe[64];
		if (sscanf(line, "nameserver %63s", probe) == 1) {
			strncpy(nsIp, probe, sizeof(nsIp) - 1);
			break;
		}
	}
	fclose(f);
	if (!nsIp[0])
		return;

	struct sockaddr_in ns;
	memset(&ns, 0, sizeof(ns));
	ns.sin_family = AF_INET;
	ns.sin_port = htons(53);
	if (inet_pton(AF_INET, nsIp, &ns.sin_addr) != 1)
		return;

	unsigned char q[300];
	int qlen = 0;
	unsigned short qid = (unsigned short)(getpid() ^ (int)ip);
	q[qlen++] = qid >> 8; q[qlen++] = qid & 0xFF;
	q[qlen++] = 0x01; q[qlen++] = 0x00; /* flags: recursion desired */
	q[qlen++] = 0x00; q[qlen++] = 0x01; /* QDCOUNT = 1 */
	q[qlen++] = 0x00; q[qlen++] = 0x00; /* ANCOUNT */
	q[qlen++] = 0x00; q[qlen++] = 0x00; /* NSCOUNT */
	q[qlen++] = 0x00; q[qlen++] = 0x00; /* ARCOUNT */

	/* in-addr.arpa requires octets in reverse order (d.c.b.a for a.b.c.d) */
	for (int i = 0; i <= 3; i++) {
		unsigned char octet = (unsigned char)((ip >> (i * 8)) & 0xFF);
		char lbl[4];
		int llen = snprintf(lbl, sizeof(lbl), "%u", octet);
		q[qlen++] = (unsigned char)llen;
		memcpy(q + qlen, lbl, llen);
		qlen += llen;
	}
	q[qlen++] = 7; memcpy(q + qlen, "in-addr", 7); qlen += 7;
	q[qlen++] = 4; memcpy(q + qlen, "arpa", 4); qlen += 4;
	q[qlen++] = 0x00;           /* end of QNAME */
	q[qlen++] = 0x00; q[qlen++] = 0x0C; /* QTYPE = PTR */
	q[qlen++] = 0x00; q[qlen++] = 0x01; /* QCLASS = IN */

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return;
	if (sendto(fd, q, qlen, 0, (struct sockaddr *)&ns, sizeof(ns)) < 0) {
		close(fd);
		return;
	}

	struct pollfd pfd;
	pfd.fd = fd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, DNS_TIMEOUT_MS) <= 0) {
		close(fd);
		return;
	}

	unsigned char resp[512];
	ssize_t rlen = recv(fd, resp, sizeof(resp), 0);
	close(fd);
	if (rlen < 12)
		return;

	unsigned short rid = (unsigned short)((resp[0] << 8) | resp[1]);
	int rcode = resp[3] & 0x0F;
	int ancount = (resp[6] << 8) | resp[7];
	if (rid != qid || rcode != 0 || ancount == 0)
		return;

	char skip[DNS_NAME_MAX];
	int pos = 12;
	int n = nm_dns_read_name(resp, (int)rlen, pos, skip, sizeof(skip));
	if (n < 0)
		return;
	pos += n + 4; /* + QTYPE/QCLASS */

	for (int i = 0; i < ancount && pos < (int)rlen; i++) {
		int rn = nm_dns_read_name(resp, (int)rlen, pos, skip, sizeof(skip));
		if (rn < 0)
			return;
		pos += rn;
		if (pos + 10 > (int)rlen)
			return;
		int type = (resp[pos] << 8) | resp[pos + 1];
		int rdlen = (resp[pos + 8] << 8) | resp[pos + 9];
		pos += 10;
		if (pos + rdlen > (int)rlen)
			return;
		if (type == 12) { /* PTR */
			char name[DNS_NAME_MAX];
			if (nm_dns_read_name(resp, (int)rlen, pos, name, sizeof(name)) > 0 &&
			    !nm_looks_like_isp_wildcard(name, ip)) {
				nm_sanitize_hostname(name);
				strncpy(out, name, outsz - 1);
				out[outsz - 1] = '\0';
			}
			return;
		}
		pos += rdlen;
	}
}

typedef struct {
	uint32_t ip;
	char name[DNS_NAME_MAX];
} nm_dns_cache_t;

/* Resolves ip via nm_dns_reverse_lookup(), caching per unique ip so a host
 * with several open ports is only queried once. Returns "" (never NULL)
 * if unresolved. Caller must hold g_netscan_mutex (static cache). */
static const char *nm_dns_resolve_cached(uint32_t ip)
{
	static nm_dns_cache_t cache[NETSCAN_MAX_OPEN];
	static int count = 0;

	for (int i = 0; i < count; i++)
		if (cache[i].ip == ip)
			return cache[i].name;
	if (count >= NETSCAN_MAX_OPEN)
		return "";

	nm_dns_cache_t *e = &cache[count++];
	e->ip = ip;
	e->name[0] = '\0';
	nm_dns_reverse_lookup(ip, e->name, sizeof(e->name));
	return e->name;
}

#define NM_MAX_OWN_IPS 16

/* Fills outIps[] (host order) with every non-loopback IPv4 address currently
 * assigned to this box, across all interfaces - a box can have more than one
 * (LAN + WiFi, an alias, ...), so a single caller-supplied address isn't
 * enough to reliably exclude ourselves from a scan. Returns the count
 * written (capped at maxIps). */
static int nm_get_own_ipv4_addrs(uint32_t *outIps, int maxIps)
{
	struct ifaddrs *ifaddr = NULL;
	if (getifaddrs(&ifaddr) != 0)
		return 0;
	int count = 0;
	for (struct ifaddrs *ifa = ifaddr; ifa && count < maxIps; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr || (ifa->ifa_flags & IFF_LOOPBACK))
			continue;
		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;
		outIps[count++] = ntohl(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr);
	}
	freeifaddrs(ifaddr);
	return count;
}

/* Core scan: probes every host in (network, broadcast) except this box's own
 * addresses against ports[], reverse-DNS-resolves whatever answered, writes
 * NETSCAN_PATH. Own addresses are skipped (see nm_get_own_ipv4_addrs()) so
 * this box never shows up as a discoverable network share of itself. Caller
 * must hold g_netscan_mutex - this function touches the static result/
 * DNS-cache buffers above and isn't safe to run concurrently with itself.
 * Silently does nothing if the host count is out of range (0 or >
 * NETSCAN_MAX_HOSTS, i.e. bigger than a /24). */
static void nm_netscan_core(uint32_t network, uint32_t broadcast, const uint16_t *ports, int portCount)
{
	uint32_t hostCount = (broadcast > network + 1) ? (broadcast - network - 1) : 0;
	if (hostCount == 0 || hostCount > NETSCAN_MAX_HOSTS)
		return;

	uint32_t ownIps[NM_MAX_OWN_IPS];
	int ownIpCount = nm_get_own_ipv4_addrs(ownIps, NM_MAX_OWN_IPS);

	static nm_scan_open_t openResults[NETSCAN_MAX_OPEN];
	int openCount = 0;

	nm_scan_slot_t slots[NETSCAN_BATCH];
	int slotCount = 0;

	for (uint32_t h = network + 1; h < broadcast; h++) {
		bool isOwn = false;
		for (int oi = 0; oi < ownIpCount; oi++) {
			if (ownIps[oi] == h) {
				isOwn = true;
				break;
			}
		}
		if (isOwn)
			continue;
		for (int pi = 0; pi < portCount; pi++) {
			if (slotCount == NETSCAN_BATCH) {
				nm_scan_run_batch(slots, slotCount, openResults, &openCount, NETSCAN_MAX_OPEN);
				slotCount = 0;
			}

			int fd = socket(AF_INET, SOCK_STREAM, 0);
			if (fd < 0)
				continue;
			int flags = fcntl(fd, F_GETFL, 0);
			fcntl(fd, F_SETFL, flags | O_NONBLOCK);

			struct sockaddr_in dst;
			memset(&dst, 0, sizeof(dst));
			dst.sin_family = AF_INET;
			dst.sin_port = htons(ports[pi]);
			dst.sin_addr.s_addr = htonl(h);

			int cr = connect(fd, (struct sockaddr *)&dst, sizeof(dst));
			if (cr == 0) {
				/* connected instantly (rare, e.g. same box) */
				if (openCount < NETSCAN_MAX_OPEN) {
					openResults[openCount].ip = h;
					openResults[openCount].port = ports[pi];
					openCount++;
				}
				close(fd);
				continue;
			}
			if (errno != EINPROGRESS) {
				close(fd);
				continue;
			}

			slots[slotCount].ip = h;
			slots[slotCount].port = ports[pi];
			slots[slotCount].fd = fd;
			slotCount++;
		}
	}
	if (slotCount > 0)
		nm_scan_run_batch(slots, slotCount, openResults, &openCount, NETSCAN_MAX_OPEN);

	static char buf[8192];
	int off = 0;
	off += snprintf(buf + off, sizeof(buf) - off, "{\n  \"scan\": [\n");
	for (int i = 0; i < openCount && off < (int)sizeof(buf) - 100; i++) {
		struct in_addr a;
		a.s_addr = htonl(openResults[i].ip);
		char ipbuf[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));
		const char *hostname = nm_dns_resolve_cached(openResults[i].ip);
		off += snprintf(buf + off, sizeof(buf) - off,
			"%s    {\"address\": \"%s\", \"port\": %u, \"state\": \"open\", \"hostname\": \"%s\"}",
			i == 0 ? "" : ",\n", ipbuf, openResults[i].port, hostname);
	}
	off += snprintf(buf + off, sizeof(buf) - off, "\n  ]\n}\n");

	FILE *out = fopen(NETSCAN_TMP, "w");
	if (!out) {
		LOG("netscan: cannot write %s: %s\n", NETSCAN_TMP, strerror(errno));
		return;
	}
	fputs(buf, out);
	fclose(out);
	rename(NETSCAN_TMP, NETSCAN_PATH);
	if (verbose)
		LOG("netscan: wrote %s (%d open of %u scanned)\n", NETSCAN_PATH, openCount, hostCount);
}

/* Parses "a.b.c.d/prefix,port[,port...]" and runs nm_netscan_core(). Caller
 * must hold g_netscan_mutex. Returns 0 if the scan ran (regardless of how
 * many ports came back open), 1 on a parameter error. */
static int doNetscan(const char *data)
{
	char dataCopy[256];
	strncpy(dataCopy, data, sizeof(dataCopy) - 1);
	dataCopy[sizeof(dataCopy) - 1] = '\0';

	char *saveptr = NULL;
	char *cidrPart = strtok_r(dataCopy, ",", &saveptr);
	if (!cidrPart)
		return 1;

	char *slash = strchr(cidrPart, '/');
	if (!slash)
		return 1;
	*slash = '\0';
	int prefix = atoi(slash + 1);
	if (prefix < 8 || prefix > 30)
		return 1;

	struct in_addr netAddr;
	if (inet_pton(AF_INET, cidrPart, &netAddr) != 1)
		return 1;

	uint16_t ports[NETSCAN_MAX_PORTS];
	int portCount = 0;
	char *portTok;
	while ((portTok = strtok_r(NULL, ",", &saveptr)) != NULL && portCount < NETSCAN_MAX_PORTS) {
		int p = atoi(portTok);
		if (p <= 0 || p > 65535)
			continue;
		ports[portCount++] = (uint16_t)p;
	}
	if (portCount == 0)
		return 1;

	uint32_t base = ntohl(netAddr.s_addr);
	uint32_t hostBits = 32 - (uint32_t)prefix;
	uint32_t network = base & (~0u << hostBits);
	uint32_t broadcast = network | ~(~0u << hostBits);

	nm_netscan_core(network, broadcast, ports, portCount);
	return 0;
}

/* Reads ifindex's IPv4 address + prefix length via SIOCGIFADDR/
 * SIOCGIFNETMASK. Returns 0 on any failure (no address assigned yet,
 * ioctl error, ...), 1 on success. */
static int nm_get_ifindex_ipv4(unsigned int ifindex, uint32_t *outIp, int *outPrefix)
{
	char ifname[IFNAMSIZ] = {0};
	if (!if_indextoname(ifindex, ifname))
		return 0;

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return 0;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) { close(sock); return 0; }
	uint32_t ip = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0) { close(sock); return 0; }
	uint32_t mask = ntohl(((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr);
	close(sock);

	if (ip == 0 || mask == 0 || mask == 0xFFFFFFFF)
		return 0;

	*outIp = ip;
	*outPrefix = __builtin_popcount(mask);
	return 1;
}

/* Unattended discovery: waits (polling every second) until the interface
 * owning the system's default route has a usable IPv4 address, then runs
 * nm_netscan_core() against that interface's subnet with fixed SMB/NFS
 * ports, sleeps 3s (lets ARP/routing settle a little further, catches
 * neighbors that were still INCOMPLETE on the first pass), and scans once
 * more. Ports are fixed (not caller-specified) since this runs unattended
 * with no caller to ask.
 *
 * The "wait until ready" loop can block for as long as the box takes to
 * get an IP (DHCP still negotiating, cable unplugged, WiFi not yet
 * associated - could be indefinite). monitor_thread()'s own while(running)
 * loop is its actual job (LINK/IP/IFACE events, the daemon_net.socket
 * accept()) and must keep running regardless, so this never runs inline in
 * that thread - see nm_autoscan_thread() below, spawned once at startup. */
static void nm_run_autoscan(void)
{
	static const uint16_t ports[] = { 445, 2049 };
	uint32_t ip = 0;
	int prefix = 0;

	while (running) {
		struct nm_default_route routes[NM_MAX_DEFAULT_ROUTES];
		unsigned int winner = 0;
		nm_scan_default_routes(routes, NM_MAX_DEFAULT_ROUTES, &winner);
		if (winner != 0 && nm_get_ifindex_ipv4(winner, &ip, &prefix) &&
		    prefix >= 8 && prefix <= 30)
			break;
		sleep(1);
	}
	if (!running)
		return;

	uint32_t hostBits = 32 - (uint32_t)prefix;
	uint32_t network = ip & (~0u << hostBits);
	uint32_t broadcast = network | ~(~0u << hostBits);

	pthread_mutex_lock(&g_netscan_mutex);
	nm_netscan_core(network, broadcast, ports, 2);
	pthread_mutex_unlock(&g_netscan_mutex);

	sleep(3);
	if (!running)
		return;

	pthread_mutex_lock(&g_netscan_mutex);
	nm_netscan_core(network, broadcast, ports, 2);
	pthread_mutex_unlock(&g_netscan_mutex);
}

static void *nm_autoscan_thread(void *arg)
{
	(void)arg;
	nm_run_autoscan();
	return NULL;
}

int processMessage(char *inData)
{
	char *tmp;
	char command[32];
	char data[256];
	char cmd[512];
	int rc;

	tmp = strchr(inData, ',');

	if (tmp)
	{
		size_t clen = (size_t)(tmp - inData);
		if (clen >= sizeof(command))
			return -1;
		strncpy(command, inData, clen);
		command[clen] = '\0';
		strncpy(data, tmp + 1, sizeof(data) - 1);
		data[sizeof(data) - 1] = '\0';
	}
	else
	{
		strncpy(command, inData, sizeof(command) - 1);
		command[sizeof(command) - 1] = '\0';
		data[0] = '\0';
	}

	/* Strip trailing newlines from command and data */
	size_t clen = strlen(command);
	while (clen > 0 && command[clen - 1] == '\n')
		command[--clen] = '\0';

	size_t dlen = strlen(data);
	while (dlen > 0 && data[dlen - 1] == '\n')
		data[--dlen] = '\0';

	if (verbose)
		LOG("processMessage Command='%s' Data='%s'\n", command, data);

	if (strcmp(command, CMD_SWITCH_CAM) == 0)
	{
		rc = system("/etc/init.d/softcam stop");
		usleep(500000);
		if (verbose)
			LOG("softcam stop -> RC %d\n", rc);
		unlink("/etc/init.d/softcam");
		char target[300];
		snprintf(target, sizeof(target), "/etc/init.d/softcam.%s", data);
		rc = symlink(target, "/etc/init.d/softcam");
		if (verbose)
			LOG("symlink softcam.%s -> RC %d\n", data, rc);
		rc = system("/etc/init.d/softcam start");
		if (verbose)
			LOG("softcam start -> RC %d\n", rc);
	}
	else if (strcmp(command, CMD_SWITCH_CARDSERVER) == 0)
	{
		rc = system("/etc/init.d/cardserver stop");
		usleep(500000);
		if (verbose)
			LOG("cardserver stop -> RC %d\n", rc);
		unlink("/etc/init.d/cardserver");
		char target[300];
		snprintf(target, sizeof(target), "/etc/init.d/cardserver.%s", data);
		rc = symlink(target, "/etc/init.d/cardserver");
		if (verbose)
			LOG("symlink cardserver.%s -> RC %d\n", data, rc);
		rc = system("/etc/init.d/cardserver start");
		if (verbose)
			LOG("cardserver start -> RC %d\n", rc);
	}
	else if (strcmp(command, CMD_IFDOWN) == 0)
	{
		/* data may be a comma-separated list of interfaces */
		char dataCopy[sizeof(data)];
		strncpy(dataCopy, data, sizeof(dataCopy) - 1);
		dataCopy[sizeof(dataCopy) - 1] = '\0';
		char *saveptr = NULL;
		char *tok = strtok_r(dataCopy, ",", &saveptr);
		rc = 0;
		while (tok)
		{
			while (*tok == ' ') tok++;
			size_t ilen = strlen(tok);
			while (ilen > 0 && tok[ilen - 1] == ' ') tok[--ilen] = '\0';
			if (ilen == 0 || ilen >= IFNAMSIZ)
				return -1;
			for (size_t i = 0; i < ilen; i++) {
				char c = tok[i];
				if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				      (c >= '0' && c <= '9') || c == '.' || c == '-' ||
				      c == ':' || c == '_'))
					return -1;
			}
			snprintf(cmd, sizeof(cmd), "/sbin/ifdown %s", tok);
			int r = system(cmd);
			if (verbose) LOG("ifdown %s -> RC %d\n", tok, r);
			if (r != 0) rc = r;
			/* ifdown doesn't reliably remove leftover addresses (e.g. a stale
			 * DHCP lease) on every setup - flush explicitly so a down interface
			 * never keeps reporting an address to netifaces/ifaddresses(). */
			snprintf(cmd, sizeof(cmd), "/sbin/ip addr flush dev %s 2>/dev/null", tok);
			int rf = system(cmd);
			if (verbose) LOG("ip addr flush dev %s -> RC %d\n", tok, rf);
			tok = strtok_r(NULL, ",", &saveptr);
		}
	}
	else if (strcmp(command, CMD_PING) == 0)
	{
		char dataCopy[sizeof(data)];
		strncpy(dataCopy, data, sizeof(dataCopy) - 1);
		dataCopy[sizeof(dataCopy) - 1] = '\0';
		char *saveptr = NULL;
		char *ifacePart = strtok_r(dataCopy, ",", &saveptr);
		char *hostPart = strtok_r(NULL, ",", &saveptr);
		if (!ifacePart || !hostPart)
			return -1;
		size_t ilen = strlen(ifacePart);
		if (ilen == 0 || ilen >= IFNAMSIZ)
			return -1;
		for (size_t i = 0; i < ilen; i++) {
			char c = ifacePart[i];
			if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			      (c >= '0' && c <= '9') || c == '.' || c == '-' ||
			      c == ':' || c == '_'))
				return -1;
		}
		int ok = (doPing(ifacePart, hostPart, 2000) == 0);
		if (verbose) LOG("ping %s via %s -> %s\n", hostPart, ifacePart, ok ? "OK" : "FAIL");
		rc = ok ? 0 : (1 << 8);
	}
	else if (strcmp(command, CMD_RESOLVE) == 0)
	{
		int ok = (doResolve(data) == 0);
		if (verbose) LOG("resolve %s -> %s\n", data, ok ? "OK" : "FAIL");
		rc = ok ? 0 : (1 << 8);
	}
	else if (strcmp(command, CMD_NETSCAN) == 0)
	{
		pthread_mutex_lock(&g_netscan_mutex);
		int ok = (doNetscan(data) == 0);
		pthread_mutex_unlock(&g_netscan_mutex);
		if (verbose) LOG("netscan %s -> %s\n", data, ok ? "OK" : "FAIL");
		rc = ok ? 0 : (1 << 8);
	}
	else
	{
		if (strcmp(command, CMD_RESTART) == 0)
		{
			snprintf(cmd, sizeof(cmd), "/etc/init.d/%s restart", data);
		}
		else if (strcmp(command, CMD_STOP) == 0)
		{
			snprintf(cmd, sizeof(cmd), "/etc/init.d/%s stop", data);
		}
		else if (strcmp(command, CMD_START) == 0)
		{
			snprintf(cmd, sizeof(cmd), "/etc/init.d/%s start", data);
		}
		else if (strcmp(command, CMD_NETRESTART) == 0)
		{
			if (strlen(data) > 0)
				snprintf(cmd, sizeof(cmd), "%s restart %s", NETRESTARTER_SH, data);
			else
				snprintf(cmd, sizeof(cmd), "%s restart", NETRESTARTER_SH);
		}
		else if (strcmp(command, CMD_IFUP) == 0 || strcmp(command, CMD_WLANDOWN) == 0)
		{
			/* single interface only */
			size_t ilen = strlen(data);
			if (ilen == 0 || ilen >= IFNAMSIZ)
				return -1;
			for (size_t i = 0; i < ilen; i++) {
				char c = data[i];
				if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				      (c >= '0' && c <= '9') || c == '.' || c == '-' ||
				      c == ':' || c == '_'))
					return -1;
			}
			if (strcmp(command, CMD_IFUP) == 0)
				snprintf(cmd, sizeof(cmd), "/sbin/ifup %s", data);
			else
				snprintf(cmd, sizeof(cmd), "%s stop %s", WLANACTIVATOR_SH, data);
		}
		else if (strcmp(command, CMD_WLANUP) == 0)
		{
			/* data = "<iface>[,<networkId>]" - networkId pins wpa_supplicant to
			 * exactly that one saved network (wpa_cli select_network in
			 * wlanactivator) instead of letting it auto-pick/roam among every
			 * enabled network in wpa_supplicant.conf. */
			char dataCopy[sizeof(data)];
			strncpy(dataCopy, data, sizeof(dataCopy) - 1);
			dataCopy[sizeof(dataCopy) - 1] = '\0';
			char *saveptr = NULL;
			char *ifacePart = strtok_r(dataCopy, ",", &saveptr);
			char *netIdPart = strtok_r(NULL, ",", &saveptr);
			if (!ifacePart)
				return -1;
			size_t ilen = strlen(ifacePart);
			if (ilen == 0 || ilen >= IFNAMSIZ)
				return -1;
			for (size_t i = 0; i < ilen; i++) {
				char c = ifacePart[i];
				if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				      (c >= '0' && c <= '9') || c == '.' || c == '-' ||
				      c == ':' || c == '_'))
					return -1;
			}
			if (netIdPart)
			{
				size_t nlen = strlen(netIdPart);
				if (nlen == 0 || nlen >= 16)
					return -1;
				for (size_t i = 0; i < nlen; i++) {
					if (netIdPart[i] < '0' || netIdPart[i] > '9')
						return -1;
				}
				snprintf(cmd, sizeof(cmd), "%s start %s %s", WLANACTIVATOR_SH, ifacePart, netIdPart);
			}
			else
				snprintf(cmd, sizeof(cmd), "%s start %s", WLANACTIVATOR_SH, ifacePart);
		}
		else
			return -1;

		rc = system(cmd);
		if (verbose)
			LOG("RC %d\n", rc);
	}
	return rc;
}
