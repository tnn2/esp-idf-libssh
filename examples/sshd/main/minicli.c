#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include "example.h"

char next_command[16];
uint8_t next_command_idx = 0;

static void minicli_command_banner(struct interactive_session *);
static void minicli_command_help(struct interactive_session *);
static void minicli_command_noop(struct interactive_session *);

struct minicli_command {
	char *cmd;
	void (*handler)(struct interactive_session *);
};

struct minicli_command minicli_commands[] = {
	{ "banner", minicli_command_banner},
	{ "help", minicli_command_help},
	{ "", minicli_command_noop},
	{ NULL, NULL }
};

void
minicli_printf(struct interactive_session *is, const char *fmt, ...)
{
	char tmp[512];
	int i;
	va_list args;

	va_start (args, fmt);
	vsnprintf(tmp, sizeof(tmp), fmt, args);
	va_end (args);
	for (i = 0; i < sizeof(tmp); i++) {
		if (tmp[i] == 0) {
			return;
		} else {
			if (tmp[i] == '\n')
				is->is_handle_char_from_local(is, '\r');
			is->is_handle_char_from_local(is, tmp[i]);
		}
	}
}

static void
minicli_command_noop(struct interactive_session *is)
{
}

static const char banner[] = "\n"
	   " _  _     _ _        __      __       _    _\n"
	   "| || |___| | |___    \\ \\    / /__ _ _| |__| |\n"
	   "| __ / -_) | / _ \\_   \\ \\/\\/ / _ \\ '_| / _` |\n"
	   "|_||_\\___|_|_\\___( )   \\_/\\_/\\___/_| |_\\__,_|\n"
	   "                 |/\n"
	   "Welcome to minicli! Type ^D to exit and 'help' for help.\n";


static void
minicli_command_banner(struct interactive_session *is)
{
	minicli_printf(is, banner);
}

static void
minicli_command_help(struct interactive_session *is)
{
	struct minicli_command *cc;

	cc = minicli_commands;
	while (cc->cmd != NULL) {
		minicli_printf(is, "	%s\n", cc->cmd);
		cc++;
	}
}

static void
minicli_prompt(struct interactive_session *is)
{
	minicli_printf(is, "minicli> ");
}

void
minicli_handle_command(struct interactive_session *is, const char *cmd)
{
	struct minicli_command *cc;

	cc = minicli_commands;
	while (cc->cmd != NULL) {
		if (!strcmp(cmd, cc->cmd)) {
			cc->handler(is);
			minicli_prompt(is);
			return;
		}
		cc++;
	}
	minicli_printf(is, "%c? unknown command\n", 7);
	minicli_prompt(is);
}

static void
minicli_handle_char(struct interactive_session *is, char c)
{
	if (c == '\r') {
		minicli_printf(is, "\n");
		next_command[next_command_idx] = 0;
		minicli_handle_command(is, next_command);
		next_command_idx = 0;
	} else if (c == 3) {
		// ^C
		minicli_printf(is, "^C\n");
		next_command[next_command_idx] = 0;
		minicli_prompt(is);
	} else if (c == 4) {
		// ^D
	} else if (c == 127) {
		// backspace
		if (next_command_idx > 0) {
			minicli_printf(is, "%c %c", 8, 8);
			next_command_idx--;
		} else {
			minicli_printf(is, "%c", 7);
		}
	} else if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
		if (next_command_idx < sizeof(next_command) - 1) {
			minicli_printf(is, "%c", c);
			next_command[next_command_idx++] = c;
		}
	} else {
		// invalid chars ignored
	}
}

void
minicli_begin_interactive_session(struct interactive_session *is)
{
	is->is_handle_char_from_remote = minicli_handle_char;
	minicli_command_banner(is);
	minicli_prompt(is);
}
