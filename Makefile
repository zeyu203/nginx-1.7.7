
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile
	$(MAKE) -f objs/Makefile manpage

install:
	$(MAKE) -f objs/Makefile install

upgrade:
	/home/zeyu/Documents/nginx-1.7.7/./sbin/nginx -t

	kill -USR2 `cat /home/zeyu/Documents/nginx-1.7.7/./logs/nginx.pid`
	sleep 1
	test -f /home/zeyu/Documents/nginx-1.7.7/./logs/nginx.pid.oldbin

	kill -QUIT `cat /home/zeyu/Documents/nginx-1.7.7/./logs/nginx.pid.oldbin`
