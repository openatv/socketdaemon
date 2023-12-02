#!/bin/sh

if ! [ -x /usr/bin/socketdaemon ]; then
	exit 0
fi

case "$1" in
	start)
		/usr/bin/socketdaemon -v >> /home/root/logs/socketdebug.log 2>&1 &
		;;
	stop)
		start-stop-daemon -K -x /usr/bin/socketdaemon
		;;
	restart|reload)
		$0 stop
		$0 start
		;;
	*)
		echo "Usage: $0 {start|stop|restart}"
		exit 1
		;;
esac

exit 0
