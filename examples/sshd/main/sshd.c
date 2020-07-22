#include <stdio.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <stddef.h>
#include "example.h"
#include "sshd.h"

static void handle_char_from_local(struct interactive_session *, char);

/*
 * XXX protos for internal libssh APIs.
 * needed for non-blocking handling of listening socket.
 */
struct ssh_poll_handle_struct *ssh_bind_get_poll(struct ssh_bind_struct *);
int ssh_event_add_poll(ssh_event event, struct ssh_poll_handle_struct *);
int ssh_event_remove_poll(ssh_event event, struct ssh_poll_handle_struct *);

/*
 * Heavy API abuse here. But upstream doesn't provide a
 * native mechanism for loading host keys from memory.
 * We assume fields in "struct ssh_bind_struct" are laid
 * out in exactly this order:
 * ssh_key ecdsa;
 * ssh_key dsa;
 * ssh_key rsa;
 * ssh_key ed25519;
 * char *bindaddr;
 */
static int
import_embedded_host_key(ssh_bind sshbind, const char *base64_key)
{
	size_t ptralign = sizeof(void*);
	char buf[2048];
	char *p, *q, *e;
	ssh_key *target;
	int error;
	ssh_key probe;
	enum ssh_keytypes_e type;

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "");
	memcpy(buf, sshbind, sizeof(buf));
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR,
			     "0123456789ABCDEF0123456789ABCDEF");
	p = buf;
	e = p + sizeof(buf);
	q = (char*)sshbind;
	while (p < e) {
		if (memcmp(p, q, ptralign) != 0)
			break;
		p += ptralign;
		q += ptralign;
	}
	if (p >= e)
		return SSH_ERROR;
	probe = ssh_key_new();
	if (probe == NULL)
		return SSH_ERROR;
	error = ssh_pki_import_privkey_base64(base64_key, NULL, NULL, NULL,
					      &probe);
	type = ssh_key_type(probe);
	ssh_key_free(probe);
	if (error != SSH_OK)
		return error;
	switch (type) {
	case SSH_KEYTYPE_ECDSA_P256:
	case SSH_KEYTYPE_ECDSA_P521:
		target = (ssh_key*)((uintptr_t)sshbind + (p - buf)
				    - 4 * ptralign);
		break;
	case SSH_KEYTYPE_DSS:
		target = (ssh_key*)((uintptr_t)sshbind + (p - buf)
				    - 3 * ptralign);
		break;
	case SSH_KEYTYPE_RSA:
		target = (ssh_key*)((uintptr_t)sshbind + (p - buf)
				    - 2 * ptralign);
		break;
	case SSH_KEYTYPE_ED25519:
		target = (ssh_key*)((uintptr_t)sshbind + (p - buf)
				    - 1 * ptralign);
		break;
	default:
		return SSH_ERROR;
	}
	error = ssh_pki_import_privkey_base64(base64_key, NULL, NULL, NULL,
					      target);
	return error;
}

static struct client_ctx *
lookup_client(struct server_ctx *sc, ssh_session session)
{
	struct client_ctx *ret;

	SLIST_FOREACH(ret, &sc->sc_client_head, cc_client_list) {
		if (ret->cc_session == session)
			return ret;
	}

	return NULL;
}

static int
auth_password(ssh_session session, const char *user, const char *password,
	      void *userdata)
{
	struct server_ctx *sc = (struct server_ctx *)userdata;
	struct client_ctx *cc;
	struct ssh_user *su;

	cc = lookup_client(sc, session);
	if (cc == NULL)
		return SSH_AUTH_DENIED;
	if (cc->cc_didauth)
		return SSH_AUTH_DENIED;
	su = sc->sc_lookup_user(sc, user);
	if (su == NULL)
		return SSH_AUTH_DENIED;
	if (strcmp(password, su->su_password) != 0)
		return SSH_AUTH_DENIED;
	cc->cc_didauth = true;

	return SSH_AUTH_SUCCESS;
}

static int
auth_publickey(ssh_session session, const char *user,
    struct ssh_key_struct *pubkey, char signature_state, void *userdata)
{
	struct server_ctx *sc = (struct server_ctx *) userdata;
	struct client_ctx *cc;
	struct ssh_user *su;
	ssh_key key;
	int error;

	cc = lookup_client(sc, session);
	if (cc == NULL)
		return SSH_AUTH_DENIED;
	if (signature_state == SSH_PUBLICKEY_STATE_NONE)
		return SSH_AUTH_SUCCESS;
	if (signature_state != SSH_PUBLICKEY_STATE_VALID)
		return SSH_AUTH_DENIED;
	if (cc->cc_didauth)
		return SSH_AUTH_DENIED;
	su = sc->sc_lookup_user(sc, user);
	if (su == NULL)
		return SSH_AUTH_DENIED;
	if (su->su_base64_key  == NULL)
		return SSH_AUTH_DENIED;
	if (ssh_pki_import_pubkey_base64(su->su_base64_key, su->su_keytype,
					 &key) != SSH_OK)
		return SSH_AUTH_DENIED;
	error = ssh_key_cmp(key, pubkey, SSH_KEY_CMP_PUBLIC);
	ssh_key_free(key);
	if (error != SSH_OK)
		return SSH_AUTH_DENIED;
	cc->cc_didauth = true;

	return SSH_AUTH_SUCCESS;
}

static int
data_function(ssh_session session, ssh_channel channel, void *data, uint32_t len,
	      int is_stderr, void *userdata)
{
	struct client_ctx *cc = (struct client_ctx *)userdata;
	int i;
	char c;
	for (i = 0; i < len; i++) {
		c = ((char*)data)[i];
		if (c == 0x4) /* ^D */ {
			ssh_channel_send_eof(channel);
			ssh_channel_close(channel);
			return len;
		}
		cc->cc_is.is_handle_char_from_remote(&cc->cc_is, c);
	}
	return len;
}

static int
pty_request(ssh_session session, ssh_channel channel, const char *term,
	    int cols, int rows, int py, int px, void *userdata) {
	struct client_ctx *cc = (struct client_ctx *)userdata;

	if (cc->cc_didpty)
	    return SSH_ERROR;
	cc->cc_cols = cols;
	cc->cc_rows = rows;
	cc->cc_px = px;
	cc->cc_py = py;
	strlcpy(cc->cc_term, term, sizeof(cc->cc_term));
	cc->cc_didpty = true;

	return SSH_OK;
}

static int
shell_request(ssh_session session, ssh_channel channel, void *userdata)
{
	struct client_ctx *cc = (struct client_ctx *)userdata;
	if (cc->cc_didshell)
	    return SSH_ERROR;
	cc->cc_didshell = true;
	cc->cc_is.is_handle_char_from_local = handle_char_from_local;
	cc->cc_begin_interactive_session(&cc->cc_is);
	return SSH_OK;
}

static int exec_request(ssh_session session, ssh_channel channel,
                        const char *command, void *userdata)
{
	struct client_ctx *cc = (struct client_ctx *)userdata;
	if (cc->cc_didshell)
	    return SSH_ERROR;
	cc->cc_is.is_handle_char_from_local = handle_char_from_local;
	minicli_handle_command(&cc->cc_is, command);
	ssh_channel_send_eof(channel);
	ssh_channel_close(channel);
	return SSH_OK;
}

static int
pty_resize(ssh_session session, ssh_channel channel, int cols,
                      int rows, int py, int px, void *userdata)
{
	struct client_ctx *cc = (struct client_ctx *)userdata;

	cc->cc_cols = cols;
	cc->cc_rows = rows;
	cc->cc_px = px;
	cc->cc_py = py;

	return SSH_OK;
}

static ssh_channel
channel_open(ssh_session session, void *userdata)
{
	struct server_ctx *sc = (struct server_ctx *)userdata;
	struct client_ctx *cc;

	cc = lookup_client(sc, session);
	if (cc == NULL)
		return NULL;
	if (cc->cc_didchannel)
		return NULL;
	cc->channel_cb = (struct ssh_channel_callbacks_struct) {
		.channel_data_function = data_function,
		.channel_exec_request_function = exec_request,
		.channel_pty_request_function = pty_request,
		.channel_pty_window_change_function = pty_resize,
		.channel_shell_request_function = shell_request,
		.userdata = cc
	};
	cc->cc_channel = ssh_channel_new(session);
	ssh_callbacks_init(&cc->channel_cb);
	ssh_set_channel_callbacks(cc->cc_channel, &cc->channel_cb);
	cc->cc_didchannel = true;

	return cc->cc_channel;
}

static void
incoming_connection(ssh_bind sshbind, void *userdata)
{
	struct server_ctx  *sc = (struct server_ctx *)userdata;
	long t = 0;
	struct client_ctx *cc = calloc(1, sizeof(struct client_ctx));

	cc->cc_session = ssh_new();
	if (ssh_bind_accept(sshbind, cc->cc_session) == SSH_ERROR) {
		goto cleanup;
	}
	cc->cc_begin_interactive_session = sc->sc_begin_interactive_session;
	ssh_set_callbacks(cc->cc_session, &sc->sc_generic_cb);
	ssh_set_server_callbacks(cc->cc_session, &sc->sc_server_cb);
	ssh_set_auth_methods(cc->cc_session, sc->sc_auth_methods);
	ssh_set_blocking(cc->cc_session, 0);
	(void) ssh_options_set(cc->cc_session, SSH_OPTIONS_TIMEOUT, &t);
	(void) ssh_options_set(cc->cc_session, SSH_OPTIONS_TIMEOUT_USEC, &t);

	if (ssh_handle_key_exchange(cc->cc_session) == SSH_ERROR) {
		ssh_disconnect(cc->cc_session);
		goto cleanup;
	}
	/*
	 * Since we set the socket to non-blocking already,
	 * ssh_handle_key_exchange will return SSH_AGAIN.
	 * Start polling the socket and let the main loop drive the kex.
	 */
	SLIST_INSERT_HEAD(&sc->sc_client_head, cc, cc_client_list);
	ssh_event_add_session(sc->sc_sshevent, cc->cc_session);
	return;
cleanup:
	ssh_free(cc->cc_session);
	free(cc);
}

/*
 * Cleans up dead clients.
 */
static void
dead_eater(struct server_ctx *sc)
{
	struct client_ctx *cc;
	struct client_ctx *cc_removed = NULL;
	int status;

	SLIST_FOREACH(cc, &sc->sc_client_head, cc_client_list) {
		if (cc_removed) {
			free(cc_removed);
			cc_removed = NULL;
		}
		status = ssh_get_status(cc->cc_session);
		if (status & (SSH_CLOSED | SSH_CLOSED_ERROR)) {
			if (cc->cc_didchannel) {
				ssh_channel_free(cc->cc_channel);
			}
			ssh_event_remove_session(sc->sc_sshevent, cc->cc_session);
			ssh_free(cc->cc_session);
			SLIST_REMOVE(&sc->sc_client_head, cc, client_ctx, cc_client_list);
			cc_removed = cc;
		}
	}
	if (cc_removed) {
		free(cc_removed);
		cc_removed = NULL;
	}
}

static int
create_new_server(struct server_ctx *sc)
{
	SLIST_INIT(&sc->sc_client_head);
	sc->sc_server_cb = (struct ssh_server_callbacks_struct){
		.userdata = sc,
		.auth_password_function = auth_password,
		.auth_pubkey_function = auth_publickey,
		.channel_open_request_session_function = channel_open
	};
	sc->sc_generic_cb = (struct ssh_callbacks_struct){
		.userdata = sc
	};
	sc->sc_bind_cb = (struct ssh_bind_callbacks_struct){
		.incoming_connection = incoming_connection
	};
	ssh_callbacks_init(&sc->sc_server_cb);
	ssh_callbacks_init(&sc->sc_generic_cb);
	ssh_callbacks_init(&sc->sc_bind_cb);
	sc->sc_sshbind = ssh_bind_new();
	if (sc->sc_sshbind == NULL) {
		return SSH_ERROR;
	}
	ssh_bind_options_set(sc->sc_sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "1");
	ssh_bind_set_callbacks(sc->sc_sshbind, &sc->sc_bind_cb, sc);
	import_embedded_host_key(sc->sc_sshbind, sc->sc_host_key);
	ssh_bind_options_set(sc->sc_sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, "22");
	ssh_bind_options_set(sc->sc_sshbind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
	if(ssh_bind_listen(sc->sc_sshbind) < 0) {
		ssh_bind_free(sc->sc_sshbind);
		return SSH_ERROR;
	}
	ssh_bind_set_blocking(sc->sc_sshbind, 0);
	ssh_event_add_poll(sc->sc_sshevent, ssh_bind_get_poll(sc->sc_sshbind));

	return SSH_OK;
}

static void
terminate_server(struct server_ctx *sc)
{
	struct client_ctx *cc;

	ssh_event_remove_poll(sc->sc_sshevent, ssh_bind_get_poll(sc->sc_sshbind));
	close(ssh_bind_get_fd(sc->sc_sshbind));
	SLIST_FOREACH(cc, &sc->sc_client_head, cc_client_list) {
		ssh_silent_disconnect(cc->cc_session);
	}
	while (!SLIST_EMPTY(&sc->sc_client_head)) {
		(void) ssh_event_dopoll(sc->sc_sshevent, 100);
		dead_eater(sc);
	}
	ssh_bind_free(sc->sc_sshbind);
	free(sc);
}

int
sshd_main(struct server_ctx *sc)
{
	int error;
	ssh_event event;
	static bool time_to_die = false;

	if (ssh_init() < 0) {
		return SSH_ERROR;
	}

	event = ssh_event_new();
	if (!event)
		return SSH_ERROR;
	sc->sc_sshevent = event;
	if (create_new_server(sc) != SSH_OK)
		return SSH_ERROR;

	while (!time_to_die) {
		error = ssh_event_dopoll(sc->sc_sshevent, 1000);
		if (error == SSH_ERROR || error == SSH_AGAIN) {
			/* check if any clients are dead and consume 'em */
			dead_eater(sc);
		}
	}
	terminate_server(sc);
	ssh_event_free(event);
	ssh_finalize();

	return SSH_OK;
}

static void
handle_char_from_local(struct interactive_session *is, char c)
{
	struct client_ctx *cc = (struct client_ctx *)((uintptr_t)is - offsetof(struct client_ctx, cc_is));
	ssh_channel_write(cc->cc_channel, &c, 1);
}


