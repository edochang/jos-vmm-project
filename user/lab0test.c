#line 2 "../user/lab0test.c"
// lab0 tests
#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	cprintf("Lab 0 Test is live.\n");

    envid_t env_id = thisenv->env_id;

	cprintf("I am environment %08x.\n", env_id);
    cprintf("And I have ran %d time(s).\n", thisenv->env_runs);

    int ret = sys_env_set_status(env_id, 2);

    cprintf("Setting environment status with sys_env_set_status(), returned %d.\n", ret);
}
