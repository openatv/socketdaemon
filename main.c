#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>

#define NAME "/tmp/deamon.socket"
#define CMD_START "START"
#define CMD_STOP "STOP"
#define CMD_RESTART "RESTART"
#define CMD_SWITCH_CAM "SWITCH_SOFTCAM"
#define CMD_SWITCH_CARDSERVER "SWITCH_CARDSERVER"

static int verbose = 0;

int processMessage(char *inData);

#define eDEBUG_BUFLEN    1024

int formatTime(char *buf, int bufferSize)
{
	int pos = 0;
	struct timespec tp;
	struct tm loctime;
	struct timeval tim;

	gettimeofday(&tim, NULL);
	localtime_r(&tim.tv_sec, &loctime);
	pos += snprintf(buf + pos, bufferSize - pos, "%04d-%02d-%02d ", 
		loctime.tm_year + 1900, loctime.tm_mon + 1, loctime.tm_mday);
	pos += snprintf(buf + pos, bufferSize - pos, "%02d:%02d:%02d.%04lu ", 
		loctime.tm_hour, loctime.tm_min, loctime.tm_sec, tim.tv_usec / 100L);
	return pos;
}


void Debug(const char* fmt, ...)
{

	char buf[eDEBUG_BUFLEN];
	int pos = formatTime(buf, eDEBUG_BUFLEN);

	va_list ap;
	va_start(ap, fmt);
	int vsize = vsnprintf(buf + pos, eDEBUG_BUFLEN - pos, fmt, ap);
	va_end(ap);
	printf(buf);
}

int main(int argc, char **argv)
{

	int sock, msgsock, rval;
	struct sockaddr_un server;
	char buf[256];
	int c = 0;

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
	strcpy(server.sun_path, NAME);
	if (bind(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_un)))
	{
		perror("binding stream socket");
		exit(1);
	}

	Debug("Start\n");

	//	printf("Socket has name %s\n", server.sun_path);
	listen(sock, 5);
	for (;;)
	{
		msgsock = accept(sock, 0, 0);
		if (msgsock == -1)
			perror("accept");
		else
			do
			{
				bzero(buf, sizeof(buf));
				if ((rval = read(msgsock, buf, 256)) < 0)
					perror("reading stream message");
				else
				{
					if (strlen(buf) > 0)
					{
						if (verbose)
							Debug("processMessage %d --> '%s' \n", strlen(buf), buf);
						int rc = processMessage(buf);
						write(msgsock, "DONE", 4);
					}
				}
			} while (rval > 0);
		close(msgsock);
	}
	close(sock);
	unlink(NAME);

	Debug("END");

	return EXIT_SUCCESS;
}

int processMessage(char *inData)
{
	char *tmp;
	char command[20];
	char data[256];
	char buff[256];
	char cmd[100];
	int rc;

	buff[0] = 0;

	tmp = strchr(inData, ',');

	if (tmp)
	{
		strncpy(command, inData, tmp - inData);
		command[tmp - inData] = 0;
		strcpy(data, tmp + 1);
	}
	else
	{
		strcpy(command, inData);
		data[0] = 0;
	}

	if (verbose)
		Debug("processMessage Command='%s'\n", command);

	if (strcmp(command, CMD_SWITCH_CAM) == 0)
	{
		rc = system("/etc/init.d/softcam stop");
		usleep(500000); // wait 500 ms after stop
		if (verbose)
			Debug("Run softcam stop -> RC %d\n", rc);
		unlink("/etc/init.d/softcam");
		sprintf(cmd, "ln -s /etc/init.d/softcam.%s /etc/init.d/softcam", data);
		rc = system(cmd);
		if (verbose)
			Debug("Run cmd='%s' -> RC %d\n", cmd, rc);
		rc = system("/etc/init.d/softcam start");
		if (verbose)
			Debug("Run softcam start -> RC %d\n", rc);
	}
	else if (strcmp(command, CMD_SWITCH_CARDSERVER) == 0)
	{
		rc = system("/etc/init.d/cardserver stop");
		usleep(500000); // wait 500 ms after stop
		if (verbose)
			Debug("Run cardserver stop -> RC %d\n", rc);
		unlink("/etc/init.d/cardserver");
		sprintf(cmd, "ln -s /etc/init.d/cardserver.%s /etc/init.d/cardserver", data);
		rc = system(cmd);
		if (verbose)
			Debug("Run cmd='%s' -> RC %d\n", cmd, rc);
		rc = system("/etc/init.d/cardserver start");
		if (verbose)
			Debug("Run cardserver start -> RC %d\n", rc);
	}
	else
	{
		if (strcmp(command, CMD_RESTART) == 0)
		{
			sprintf(cmd, "/etc/init.d/%s restart", data);
		}
		else if (strcmp(command, CMD_STOP) == 0)
		{
			sprintf(cmd, "/etc/init.d/%s stop", data);
		}
		else if (strcmp(command, CMD_START) == 0)
		{
			sprintf(cmd, "/etc/init.d/%s start", data);
		}
		else
			return -1;

		rc = system(cmd);
		if (verbose)
			Debug("Run cmd='%s' -> RC %d\n", cmd, rc);
	}
	return rc;
}
