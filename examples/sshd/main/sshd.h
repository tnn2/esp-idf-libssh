struct ssh_user {
	const char				*su_user;
	const char				*su_password;
	const enum ssh_keytypes_e		su_keytype;
	const char				*su_base64_key;
};

struct client_ctx {
	ssh_session				cc_session;
	ssh_channel				cc_channel;
	struct ssh_channel_callbacks_struct	channel_cb;
	bool					cc_didauth;
	bool					cc_didchannel;
	bool					cc_didpty;
	bool					cc_didshell;
	int					cc_cols;
	int					cc_rows;
	int					cc_py;
	int					cc_px;
	char					cc_term[16];
	SLIST_ENTRY(client_ctx)			cc_client_list;
	void					(*cc_begin_interactive_session)(struct interactive_session *);
	struct interactive_session		cc_is;
};

struct server_ctx {
	ssh_event				sc_sshevent;
	ssh_bind				sc_sshbind;
	struct ssh_server_callbacks_struct	sc_server_cb;
	struct ssh_callbacks_struct		sc_generic_cb;
	struct ssh_bind_callbacks_struct	sc_bind_cb;
	int					sc_auth_methods;
	struct ssh_user *			(*sc_lookup_user)(struct server_ctx *, const char *);
	const char *				sc_host_key;
	void					(*sc_begin_interactive_session)(struct interactive_session *);
	SLIST_HEAD(, client_ctx) sc_client_head;
};

int sshd_main(struct server_ctx *sc);
