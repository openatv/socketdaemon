#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <string.h>

#define NAME "/tmp/deamon.socket"
#define CMD_START "START"
#define CMD_STOP "STOP"
#define CMD_RESTART "RESTART"
#define CMD_SWITCH_CAM "SWITCH_CAM"

void processMessage(char *inData);

int main()
{

	int sock, msgsock, rval;
	struct sockaddr_un server;
	char buf[256];

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
				// else if (rval == 0)
				// printf("Ending connection\n");
				else
					processMessage(buf);
				// printf("-->%s\n", buf);
			} while (rval > 0);
		close(msgsock);
	}
	close(sock);
	unlink(NAME);

	return EXIT_SUCCESS;
}

void processMessage(char *inData)
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

	// printf("Command='%s'\n", command);

	// Dispath out command
	if (strcmp(command, CMD_RESTART) == 0)
	{
		sprintf(cmd, "/etc/init.d/%s restart", data);
		rc = system(cmd);
	}
	else if (strcmp(command, CMD_STOP) == 0)
	{
		sprintf(cmd, "/etc/init.d/%s stop", data);
		rc = system(cmd);
	}
	else if (strcmp(command, CMD_START) == 0)
	{
		sprintf(cmd, "/etc/init.d/%s start", data);
		rc = system(cmd);
	}
	else if (strcmp(command, CMD_SWITCH_CAM) == 0)
	{
		char old[100];
		char new[100];

		tmp = strchr(data, ',');
		if(tmp)
		{
			strncpy(old, data, tmp - data);
			command[tmp - data] = 0;
			strcpy(new, tmp + 1);
			system("/etc/init.d/softcam stop");
			remove("/etc/init.d/softcam");
			sprintf(cmd, "ln -s /etc/init.d/softcam.%s /etc/init.d/softcam", new);
			system(cmd);
			system("/etc/init.d/softcam start");
		}
	}
}
