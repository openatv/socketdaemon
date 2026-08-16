#!/bin/sh

if ! [ -x /usr/bin/socketdaemon ]; then
	exit 0
fi

case "$1" in
	start)
		if grep -q "^config.crash.debugNetwork=True$" /etc/enigma2/settings 2>/dev/null; then
			start-stop-daemon -S -b -x /usr/bin/socketdaemon -- -v -l /var/log/socketdaemon.log
		else
			start-stop-daemon -S -b -x /usr/bin/socketdaemon
		fi
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
