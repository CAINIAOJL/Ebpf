#include <stdio.h>
#include <argp.h>

/*
const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"BPF bootstrap demo application.\n"
"\n"
"It traces process start and exits and shows associated \n"
"information (filename, process duration, PID and PPID, etc).\n"
"\n"
"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
    { "verbose", 'v', NULL, 0, "Verbose debug output" },
    { "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
    {},
};
*/


const char* argp_program_version = "jiangleicainiao 0.0";
const char* argp_program_bug_address = "czgxy@jianglei-f306.local";
const char argp_program_doc[] = 
    "this is a demo program for jianglei cainiao czgxy\n"
    "\n"
    "information : my first program for linux kernel programming\n"
    "\n"
    "USAGE: ./myprogram [-d ddddd] [-v vvvv] [-h hhhh]\n";

static const struct argp_option ops[] = {
    {"dddddddd", 'd', NULL, 0, "dddddddcainiao"},
    {"vvvvvvvv", 'v', NULL, 0, "vvvvvvvcainiao"},
    {"hhhhhhhh", 'h', NULL, 0, "hhhhhhhcainiao"},
    {}
};

/*
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'v':
        env.verbose = true;
        break;
    case 'd':
        errno = 0;
        env.min_duration_ms = strtol(arg, NULL, 10);
        if (errno || env.min_duration_ms <= 0) {
            fprintf(stderr, "Invalid duration: %s\n", arg);
            argp_usage(state);
        }
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
*/

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    switch (key)
    {
    case 'v':
        fprintf(stdout, "vvvvvvvvvvvvvv %s\n", arg);
        break;
    case 'd':
        fprintf(stdout, "ddddddddddddddd %s\n", arg);
        break;

    case 'h':
        fprintf(stdout, "hhhhhhhhhhhhhhh %s\n", arg);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
        break;
    }
    return 0;
}

static const struct argp argp = {
    .options = ops,
    .parser = parse_opt,
    .doc = argp_program_doc,
};

int main(int argc, char** argv) {
    int err;
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);

    if (err)
        return err;
}