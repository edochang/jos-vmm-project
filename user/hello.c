#line 2 "../user/hello.c"
// hello, world
#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	cprintf("hello, world\n");
	cprintf("i am environment %08x\n", thisenv->env_id);

	cprintf("Lab 0 Test is live.\n");

    envid_t env_id = thisenv->env_id;

	cprintf("I am environment %08x of type %d.\n", env_id, thisenv->env_type);
    cprintf("And I have ran %d time(s).\n", thisenv->env_runs);

    int ret = sys_env_set_status(env_id, 2);

    cprintf("Setting environment status with sys_env_set_status(), returned %d.\n", ret);
}
