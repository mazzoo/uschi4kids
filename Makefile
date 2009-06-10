all: uschi4kids.so


uschi4kids.so:uschi4kids.c
	$(CC) -Wall -g -shared -ldl -o $@ $^

clean:
	rm uschi4kids.so

test:uschi4kids.so
	LD_PRELOAD=./uschi4kids.so host ix.de
	LD_PRELOAD=./uschi4kids.so host unix.de

