#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <sys/queue.h>
#include "example.h"
#include "sshd.h"

/* change this */
static struct ssh_user hardcoded_example_users[] = {
	{
		.su_user = "neo",
		.su_password = "trinity",
	},
	{
		.su_user = "tnn",
		.su_keytype = SSH_KEYTYPE_ED25519,
		.su_base64_key = "AAAAC3NzaC1lZDI1NTE5AAAAILrLCwnBbitV0fhQyy7PClEDVLbtD3tzmuWX4fU6DuxI"
	},
	{
	}
};

/* obviously you'll want to replace this also */
const char *hardcoded_example_host_key =
	"-----BEGIN OPENSSH PRIVATE KEY-----\n"
	"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\n"
	"-----END OPENSSH PRIVATE KEY-----\n";

static struct ssh_user *
lookup_user(struct server_ctx *sc, const char *user)
{
	struct ssh_user *su;
	for (su = hardcoded_example_users; su->su_user; su++) {
		if (strcmp(user, su->su_user) == 0)
			return su;
	}
	return NULL;

}

void
sshd_task(void *arg)
{
	struct server_ctx *sc;
	sc = calloc(1, sizeof(struct server_ctx));
	if (!sc)
		return;
	sc->sc_host_key = hardcoded_example_host_key;
	sc->sc_lookup_user = lookup_user;
	sc->sc_begin_interactive_session = minicli_begin_interactive_session;
	sc->sc_auth_methods = SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY;
	sshd_main(sc);
}

void
start_sshd(void)
{
	xTaskCreate(sshd_task, "sshd", 32768, NULL, 10, NULL);
}
