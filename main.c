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
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <pthread.h>
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

static int verbose = 0;
static volatile sig_atomic_t running = 1;
static pthread_t g_monitor_tid;
static int g_stop_pipe[2] = {-1, -1};

int processMessage(char *inData);
static void *monitor_thread(void *arg);

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

/* TX bitrate in bps via SIOCGIWRATE; returns 0 when not available */
static int nm_get_wlan_bitrate(int sock, const char *iface)
{
	struct nm_iwreq wrq;
	memset(&wrq, 0, sizeof(wrq));
	strncpy(wrq.iw_ifname, iface, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIWRATE, &wrq) < 0)
		return 0;
	return wrq.u.param.value > 0 ? (int)wrq.u.param.value : 0;
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

/* Default gateway for iface from /proc/net/route (default route, RTF_GATEWAY set).
 * out is set to "" when no default gateway is found. */
static void nm_get_gateway(const char *iface, char *out, size_t outsz)
{
	out[0] = '\0';
	FILE *f = fopen("/proc/net/route", "r");
	if (!f) return;

	char line[256];
	if (!fgets(line, sizeof(line), f)) { fclose(f); return; } /* skip header */

	while (fgets(line, sizeof(line), f)) {
		char riface[IFNAMSIZ];
		unsigned int dest, gw, flags;
		if (sscanf(line, "%15s %X %X %X", riface, &dest, &gw, &flags) < 4)
			continue;
		if (strcmp(riface, iface) != 0) continue;
		if (dest != 0) continue;         /* default route only (0.0.0.0) */
		if (!(flags & 0x2)) continue;    /* RTF_GATEWAY must be set */
		/* /proc/net/route on LE stores IPs as little-endian hex;
		 * reading byte-by-byte gives the correct dotted-quad. */
		unsigned char *b = (unsigned char *)&gw;
		snprintf(out, outsz, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
		break;
	}
	fclose(f);
}

/* IPv6 addresses from /proc/net/if_inet6 as a JSON array.
 * out is set to "" when no addresses are found. */
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
		if (scope != 0x00) continue; /* global only */

		struct in6_addr a;
		for (int i = 0; i < 16; i++) {
			char b[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
			a.s6_addr[i] = (uint8_t)strtoul(b, NULL, 16);
		}
		char astr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &a, astr, sizeof(astr));

		int n = snprintf(out + off, outsz - off,
		                 "%s{\"addr\":\"%s\",\"prefix\":%d}",
		                 count ? "," : "", astr, plen);
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

static void nm_gather_and_write(void)
{
	static char buf[NETMON_BUF_SIZE];
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
		return;
	}

	pf = fopen("/proc/net/dev", "r");
	if (!pf) {
		LOG("netmon: cannot open /proc/net/dev: %s\n", strerror(errno));
		close(sock);
		return;
	}

	/* skip two header lines */
	if (!fgets(line, sizeof(line), pf) || !fgets(line, sizeof(line), pf)) {
		fclose(pf); close(sock); return;
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

		int wireless = nm_is_wireless(sock, iface);

		/* interface flags */
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
		int if_up = 0, if_running = 0;
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) >= 0) {
			if_up      = (ifr.ifr_flags & IFF_UP)      != 0;
			if_running = (ifr.ifr_flags & IFF_RUNNING) != 0;
		}

		/* MAC */
		macbuf[0] = '\0';
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
		if (ioctl(sock, SIOCGIFHWADDR, &ifr) >= 0) {
			unsigned char *m = (unsigned char *)ifr.ifr_hwaddr.sa_data;
			snprintf(macbuf, sizeof(macbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
				m[0], m[1], m[2], m[3], m[4], m[5]);
		}

		/* IPv4 address + prefix + mask + gateway */
		ipbuf[0] = '\0';
		char maskbuf[INET_ADDRSTRLEN] = {};
		char gwbuf[INET_ADDRSTRLEN] = {};
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
			nm_get_gateway(iface, gwbuf, sizeof(gwbuf));
		}

		/* IPv6 addresses */
		char ip6buf[512] = {};
		nm_get_ipv6(iface, ip6buf, sizeof(ip6buf));

		/* driver module name + hardware ID (PCI or USB) */
		nm_get_driver(iface, driverbuf, sizeof(driverbuf));
		nm_get_hw_id(iface, hwidbuf, sizeof(hwidbuf));

		if (verbose)
			LOG("netmon: iface=%s type=%s up=%d running=%d mac=%s ip=%s/%d driver=%s hw=%s\n",
				iface, wireless ? "wlan" : "lan",
				if_up, if_running, macbuf,
				ipbuf[0] ? ipbuf : "-", prefix,
				driverbuf[0] ? driverbuf : "-",
				hwidbuf[0]   ? hwidbuf   : "-");

		if (!first)
			off += snprintf(buf + off, sizeof(buf) - off, ",\n");
		first = 0;

		off += snprintf(buf + off, sizeof(buf) - off,
			"    \"%s\": {\n"
			"      \"type\": \"%s\",\n"
			"      \"up\": %s,\n"
			"      \"running\": %s,\n"
			"      \"mac\": \"%s\"",
			iface,
			wireless ? "wlan" : "lan",
			if_up      ? "true" : "false",
			if_running ? "true" : "false",
			macbuf);

		if (ipbuf[0]) {
			off += snprintf(buf + off, sizeof(buf) - off,
				",\n      \"ip4\": \"%s\"", ipbuf);
			if (maskbuf[0])
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"mask\": \"%s\"", maskbuf);
			if (prefix >= 0)
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"prefix4\": %d", prefix);
			if (gwbuf[0])
				off += snprintf(buf + off, sizeof(buf) - off,
					",\n      \"gw\": \"%s\"", gwbuf);
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
				int up = (ifi->ifi_flags & IFF_RUNNING) != 0;
				if (verbose) LOG("netmon: RTM_NEWLINK %s %s\n", ifname, up ? "up" : "down");
				off = nm_evt(evtbuf, off, evtmax, "LINK,%s,%s\n", ifname, up ? "up" : "down");
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

	nm_gather_and_write(); /* initial scan */

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
				/* send current state immediately */
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
			/* specific events: gather first so /var/run/netinfo is fresh */
			nm_gather_and_write();
			net_cli = nm_send_to_client(net_cli, evtbuf, evtlen);
		} else if (r == 0) {
			/* fallback poll timeout */
			if (verbose) LOG("netmon: poll timeout – refreshing\n");
			nm_gather_and_write();
			net_cli = nm_send_to_client(net_cli, "UPDATE\n", 7);
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
			tok = strtok_r(NULL, ",", &saveptr);
		}
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
		else if (strcmp(command, CMD_IFUP) == 0 ||
		         strcmp(command, CMD_WLANUP) == 0 || strcmp(command, CMD_WLANDOWN) == 0)
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
			else if (strcmp(command, CMD_WLANUP) == 0)
				snprintf(cmd, sizeof(cmd), "%s start %s", WLANACTIVATOR_SH, data);
			else
				snprintf(cmd, sizeof(cmd), "%s stop %s", WLANACTIVATOR_SH, data);
		}
		else
			return -1;

		rc = system(cmd);
		if (verbose)
			LOG("RC %d\n", rc);
	}
	return rc;
}
