/*
 * socketdaemon/main.c
 *
 * Unix Domain Socket daemon for Enigma2 / OpenATV.
 * Listens on /var/run/daemon.socket (AF_UNIX SOCK_STREAM).
 *
 * Protocol (null-terminated strings):
 *   Client sends:  "<COMMAND>[,<data>]\0"
 *   Daemon replies: "DONE\0"
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
#include <sys/un.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>

#define NAME "/var/run/daemon.socket"
#define CMD_START "START"
#define CMD_STOP "STOP"
#define CMD_RESTART "RESTART"
#define CMD_SWITCH_CAM "SWITCH_SOFTCAM"
#define CMD_SWITCH_CARDSERVER "SWITCH_CARDSERVER"
#define CMD_NETRESTART "NETRESTART"
#define NETRESTARTER_SH      "/etc/init.d/netrestarter"

static int verbose = 0;
static volatile sig_atomic_t running = 1;

int processMessage(char *inData);

static FILE *log_stream;

static void handle_signal(int sig)
{
	(void)sig;
	running = 0;
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

	if (unlink(NAME) == -1 && errno != ENOENT)
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
	strncpy(server.sun_path, NAME, sizeof(server.sun_path) - 1);
	server.sun_path[sizeof(server.sun_path) - 1] = '\0';
	if (bind(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_un)))
	{
		perror("binding stream socket");
		exit(1);
	}
	chmod(NAME, 0600);

	LOG("Start\n");

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
						int rc = processMessage(buf);

						ssize_t wr = send(msgsock, "DONE", 4, MSG_NOSIGNAL);
						if (verbose)
							LOG("write DONE --> %zd rc=%d\n", wr, rc);
					}
				}
			} while (rval > 0);
			close(msgsock);
		}
	}
	close(sock);
	unlink(NAME);

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
		else
			return -1;

		rc = system(cmd);
		if (verbose)
			LOG("RC %d\n", rc);
	}
	return rc;
}
