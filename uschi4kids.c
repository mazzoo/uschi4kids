#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>


#define FILE_UID "/etc/uschi4kids.uid"
#define FILE_URL "/etc/uschi4kids.url"

#define BUFSZ 4096
char linebuf[BUFSZ];

struct allowed_user_t {
	struct allowed_user_t * next;
	uid_t                   uid;
} * allowed_user;

struct allowed_url_t {
	struct allowed_url_t  * next;
	char                  * url;
} * allowed_url;

struct hostent invalid_host;

/**************************************************************/
/* init */

void uschi_exit(void)
{
	//printf("byebye.\n\n");
}

static int is_initialized = 0;

void init_user_list(void)
{
	allowed_user = malloc(sizeof(*allowed_user));
	if (!allowed_user)
		return; /* uh-oh, this disables all DNS */

	allowed_user->next = NULL;
	allowed_user->uid  = 0; /* allmighty root */

	FILE * fd = fopen(FILE_UID, "r");
	if (!fd)
		return;

	int lineno = 0;
	uid_t uid;
	char * end;
	struct allowed_user_t * p = allowed_user;
	while (fgets(linebuf, BUFSZ, fd)) {
		lineno++;
		/* comments and empty lines */
		if (linebuf[0] == '#')
			continue;
		if (linebuf[0] == '\n')
			continue;
		/* parse uid number */
		uid = strtol(linebuf, &end, 0);
		if (end == linebuf) {
			fprintf(stderr, "parse error in %s:%d\n",
				FILE_UID, lineno);
			goto out;
		}
		/* list handling */
		p->next = malloc(sizeof(*p->next));
		if (!p->next)
			goto out;
		p = p->next;
		/* fill in list */
		p->next = NULL;
		p->uid = uid;
		printf("allowing user %d\n", uid);
	}
out:
	fclose(fd);
}

void init_url_list(void)
{
	memset(&invalid_host, 0, sizeof(invalid_host));

	FILE * fd = fopen(FILE_URL, "r");
	if (!fd)
		return;

	struct allowed_url_t * p = allowed_url;
	while (fgets(linebuf, BUFSZ, fd)) {
		/* comments and empty lines */
		if (linebuf[0] == '#')
			continue;
		if (linebuf[0] == '\n')
			continue;
		/* list handling */
		if (!p) {
			p = malloc(sizeof(*p));
			allowed_url = p;
		} else {
			p->next = malloc(sizeof(*p->next));
			p = p->next;
		}
		if (!p)
			goto out;
		p->next = NULL;
		/* chop */
		if (linebuf[strlen(linebuf)-1] == '\n')
			linebuf[strlen(linebuf)-1] = 0;
		/* fill in list */
		p->url = strndup(linebuf, BUFSZ);
		printf("allowing url %s\n", p->url);
	}
out:
	fclose(fd);
}

static inline void init(void)
{
	if (is_initialized)
		return;
	atexit(uschi_exit);

	init_user_list();
	init_url_list();

	is_initialized++;
}

/**************************************************************/
/* checking legacy users/URLs */

int is_allowed_user(uid_t uid)
{
	struct allowed_user_t *p = allowed_user;
	while (p) {
		if (uid == p->uid)
			return 1;
		p = p->next;
	}
	return 0;
}
int is_allowed_url(const char * url)
{
	struct allowed_url_t *p = allowed_url;
	while (p) {
		if (!strcmp(url, p->url))
			return 1;
		p = p->next;
	}
	return 0;
}

int is_allowed(const char * url)
{
	if (is_allowed_user(getuid()))
		return 1;
	if (is_allowed_url(url))
		return 1;
	return 0;

}

/**************************************************************/
/* hijacked functions */

struct hostent *gethostbyname(const char *name)
{
	init();
	static void * (*func)();
	if (!func)
		func = (void *(*)()) dlsym(RTLD_NEXT, "gethostbyname");

	if (!is_allowed(name))
		return &invalid_host;

	return func(name);
}

struct hostent *gethostbyname2(const char *name, int af)
{
	init();
	static void * (*func)();
	if (!func)
		func = (void *(*)()) dlsym(RTLD_NEXT, "gethostbyname2");

	if (!is_allowed(name))
		return &invalid_host;

	return func(name, af);
}

struct hostent *gethostent(void)
{
	init();
	static void * (*func)();
	if (!func)
		func = (void *(*)()) dlsym(RTLD_NEXT, "gethostent");

	struct hostent * try = func();

	if (is_allowed(try->h_name))
		return try;
	else
		return &invalid_host;
}

int gethostbyname_r(const char *name,
		struct hostent *ret, char *buf, size_t buflen,
		struct hostent **result, int *h_errnop)
{
	init();
	static int (*func)();
	if (!func)
		func = (int (*)()) dlsym(RTLD_NEXT, "gethostbyname_r");

	if (!is_allowed(name)) {
		result = NULL;
		return -23;
	}

	return func(name, ret, buf, buflen, result, h_errnop);
}

int gethostbyname2_r(const char *name, int af,
		struct hostent *ret, char *buf, size_t buflen,
		struct hostent **result, int *h_errnop)
{
	init();
	static int (*func)();
	if (!func)
		func = (int (*)()) dlsym(RTLD_NEXT, "gethostbyname2_r");

	if (!is_allowed(name)) {
		result = NULL;
		return -23;
	}

	return func(name, af, ret, buf, buflen, result, h_errnop);
}

int gethostent_r(
		struct hostent *ret, char *buf, size_t buflen,
		struct hostent **result, int *h_errnop)
{
	init();
	static int (*func)();
	if (!func)
		func = (int (*)()) dlsym(RTLD_NEXT, "gethostent_r");

	if (!is_allowed(buf)) {
		result = NULL;
		return -23;
	}

	return func(ret, buf, buflen, result, h_errnop);
}


int inet_pton(int af, const char *src, void *dst)
{
	init();
	static int (*func)();
	if (!func)
		func = (int (*)()) dlsym(RTLD_NEXT, "inet_pton");

	if (!is_allowed(src)) {
		dst = NULL;
		return 0;
	}

	return func(af, src, dst);
}

int getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints,
		struct addrinfo **res)
{
	init();
	static int (*func)();
	if (!func)
		func = (int (*)()) dlsym(RTLD_NEXT, "getaddrinfo");

	if (!is_allowed(node)) {
		res = NULL;
		return -EAI_FAIL;
	}
	return func(node, service, hints, res);
}
