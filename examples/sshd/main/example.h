void initialize_wifi(void);
void wifi_sta_join(const char* ssid, const char* pass);
void start_sshd(void);

struct interactive_session {
	void	(*is_handle_char_from_remote)(struct interactive_session *, char);
	void	(*is_handle_char_from_local)(struct interactive_session *, char);
	void	*is_data;
};

void minicli_handle_command(struct interactive_session *, const char *);
void minicli_begin_interactive_session(struct interactive_session *);

