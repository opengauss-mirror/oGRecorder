#ifndef WR_CMD_CONN_OPT
#define WR_CMD_CONN_OPT

/* get opt connection */
wr_conn_t* wr_get_connection_opt(const char *input_args);

/* get opt connection status */
bool8 wr_get_connection_opt_status();

/* disconnection opt connection */
void wr_conn_opt_exit();

#endif
