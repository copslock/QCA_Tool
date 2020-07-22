/*
 * Copyright (c) 2019-2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

/*
 * @file netlink socket handler
 */

#include <nss_nlbase.h>
#include <nss_nlsock_api.h>

/*
 * nss_nlsock_init()
 * 	initialize the socket and callback
 */
static int nss_nlsock_init(struct nss_nlsock_ctx *sock, nl_recvmsg_msg_cb_t cb)
{
	int error;

	assert(sock);

	error = pthread_spin_init(&sock->lock, PTHREAD_PROCESS_PRIVATE);
	if (error) {
		nss_nlsock_log_error("Failed to init spinlock for family(%s), error %d\n", sock->family_name, error);
		return error;
	}

	sock->pid = getpid();

	/*
	 * Create netlink socket
	 */
	sock->nl_sk = nl_socket_alloc();
	if (!sock->nl_sk) {
		nss_nlsock_log_error("%d:failed to alloc socket for family(%s)\n", sock->pid, sock->family_name);
		goto fail1;
	}

	/*
	 * create callback
	 */
	sock->nl_cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!sock->nl_cb) {
		nss_nlsock_log_error("%d:failed to alloc callback for family(%s)\n",sock->pid, sock->family_name);
		goto fail2;
	}

	nl_cb_set(sock->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, cb, sock);
	sock->ref_cnt = 1;

	return 0;

fail2:
	nl_socket_free(sock->nl_sk);
	sock->nl_sk = NULL;
fail1:
	pthread_spin_destroy(&sock->lock);
	sock->lock = (pthread_spinlock_t)0;
	return ENOMEM;
}

/*
 * nss_nlsock_deinit()
 * 	de-initialize the socket
 */
static void nss_nlsock_deinit(struct nss_nlsock_ctx *sock)
{
	assert(sock);

	sock->ref_cnt = 0;

	nl_cb_put(sock->nl_cb);
	sock->nl_cb = NULL;

	nl_socket_free(sock->nl_sk);
	sock->nl_sk = NULL;
}

/*
 * nss_nlsock_ref()
 * 	if ref_cnt == 0, return false
 * 	if ref_cnt != 0, increment the socket reference count and return true
 */
static inline bool nss_nlsock_ref(struct nss_nlsock_ctx *sock)
{
	pthread_spin_lock(&sock->lock);

	/*
	 * if, there are no references it means that the socket
	 * is freed
	 */
	if (sock->ref_cnt == 0) {
		pthread_spin_unlock(&sock->lock);
		return false;
	}

	sock->ref_cnt++;
	pthread_spin_unlock(&sock->lock);

	return true;
}

/*
 * nss_nlsock_deref()
 * 	decrement the reference count and free socket resources if '0'
 */
static inline void nss_nlsock_deref(struct nss_nlsock_ctx *sock)
{
	assert(sock->ref_cnt > 0);

	pthread_spin_lock(&sock->lock);

	if (--sock->ref_cnt) {
		pthread_spin_unlock(&sock->lock);
		return;
	}

	nss_nlsock_deinit(sock);
	pthread_spin_unlock(&sock->lock);

	pthread_spin_destroy(&sock->lock);
	sock->lock = (pthread_spinlock_t)0;
}

/*
 * nss_nlsock_sync()
 *	drain out pending responses from the netlink socket
 *
 * Note: this thread is woken up whenever someone sends a NL message.
 * Thread blocks on the socket for data and comes out when
 * 1. Data is available on the socket
 * 2. or a callback has returned NL_STOP
 * 3. or the socket is configured for non-blocking
 */
static void *nss_nlsock_sync(void *arg)
{
	struct nss_nlsock_ctx *sock = (struct nss_nlsock_ctx *)arg;
	assert(sock);

	/*
	 * drain responses on the socket
	 */
	for (;;) {

		/*
		 * if, socket is freed then break out
		 */
		if (!nss_nlsock_ref(sock)) {
			break;
		}

		/*
		 * get or block for pending messages
		 */
	        nl_recvmsgs(sock->nl_sk, sock->nl_cb);
		nss_nlsock_deref(sock);

	}

	return NULL;
}

/*
 * nss_nlsock_open_mcast()
 * 	Open the socket for async events
 */
int nss_nlsock_open_mcast(struct nss_nlsock_ctx *sock, nl_recvmsg_msg_cb_t cb)
{
	int error;

	if (!sock) {
		nss_nlsock_log_error("Invalid NSS Socket context\n");
		return EINVAL;
	}

	error = nss_nlsock_init(sock, cb);
	if (error) {
		return error;
	}

	/*
	 * Disable seq number and auto ack checks for sockets listening for mcast events
	 */
	nl_socket_disable_seq_check(sock->nl_sk);
	nl_socket_disable_auto_ack(sock->nl_sk);

	/*
	 * Connect the socket with the netlink bus
	 */
	if (genl_connect(sock->nl_sk)) {
		nss_nlsock_log_error("%d:failed to connect socket for family(%s)\n", sock->pid, sock->family_name);
		error = EBUSY;
		goto free_sock;
	}
	return 0;

free_sock:
	nss_nlsock_deref(sock);
	return error;
}

/*
 * nss_nlsock_join_grp()
 *      nl socket subscribe for the multicast group
 */
int nss_nlsock_join_grp(struct nss_nlsock_ctx *sock, char *grp_name)
{
	int error;

	assert(sock->ref_cnt > 0);

	/*
	 * Resolve the group
	 */
	sock->grp_id = genl_ctrl_resolve_grp(sock->nl_sk, sock->family_name, grp_name);
	if (sock->grp_id < 0) {
		nss_nlsock_log_error("failed to resolve group(%s)\n", grp_name);
		return EINVAL;
	}

	/*
	 * Subscribe for the mcast async events
	 */
	error = nl_socket_add_memberships(sock->nl_sk, sock->grp_id, 0);
	if (error < 0) {
		nss_nlsock_log_error("failed to register grp(%s)\n", grp_name);
		return error;
	}

	return 0;
}

/*
 * nss_nlsock_leave_grp()
 *      nl socket unsubscribe for the multicast group
 */
int nss_nlsock_leave_grp(struct nss_nlsock_ctx *sock, char *grp_name)
{
	int error;

	assert(sock->ref_cnt > 0);

	/*
	 * Resolve the group
	 */
	sock->grp_id = genl_ctrl_resolve_grp(sock->nl_sk, sock->family_name, grp_name);
	if (sock->grp_id < 0) {
		nss_nlsock_log_error("failed to resolve group(%s)\n", grp_name);
		return EINVAL;
	}

	/*
	 * Unsubscribe for the mcast async events
	 */
	error = nl_socket_drop_memberships(sock->nl_sk, sock->grp_id, 0);
	if (error < 0) {
		nss_nlsock_log_error("failed to deregister grp(%s)\n", grp_name);
		return error;
	}

	return 0;
}

/*
 * nss_nlsock_listen()
 *      listen for async events on the socket
 */
int nss_nlsock_listen(struct nss_nlsock_ctx *sock)
{
	int error;

	assert(sock->ref_cnt > 0);

	/*
	 * Create the sync thread for clearing the pending resp on the socket
	 */
	error = pthread_create(&sock->thread, NULL, nss_nlsock_sync, sock);
	if (error) {
		nss_nlsock_log_error("failed to create sync thread for family(%s)\n", sock->family_name);
		return error;
	}

	return 0;
}

/*
 * nss_nlsock_open()
 *	open a socket for unicast communication with the generic netlink framework
 */
int nss_nlsock_open(struct nss_nlsock_ctx *sock, nl_recvmsg_msg_cb_t cb)
{
	int error = 0;

	if (!sock) {
		nss_nlsock_log_error("Invalid NSS Socket context\n");
		return EINVAL;
	}

	error = nss_nlsock_init(sock, cb);
	if (error) {
		return error;
	}

	/*
	 * Connect the socket with the netlink bus
	 */
	if (genl_connect(sock->nl_sk)) {
		nss_nlsock_log_error("%d:failed to connect socket for family(%s)\n", sock->pid, sock->family_name);
		error = EBUSY;
		goto free_sock;
	}

	/*
	 * resolve the family
	 */
	sock->family_id = genl_ctrl_resolve(sock->nl_sk, sock->family_name);
	if (sock->family_id <= 0) {
		nss_nlsock_log_error("%d:failed to resolve family(%s)\n", sock->pid, sock->family_name);
		error = EINVAL;
		goto free_sock;
	}

	/*
	 * Since, we will be listening for events it needs to switch to non-blocking mode
	 */
	nl_socket_set_nonblocking(sock->nl_sk);

	/*
	 * create the sync thread for clearing the pending resp on the socket
	 */
	error = pthread_create(&sock->thread, NULL, nss_nlsock_sync, sock);
	if (error) {
		nss_nlsock_log_error("%d:failed to create sync thread for family(%s)\n", sock->pid, sock->family_name);
		goto free_sock;
	}

	return 0;

free_sock:

	nss_nlsock_deref(sock);
	return error;
}

/*
 * nss_nlsock_close()
 * 	close the allocated socket and all associated memory
 */
void nss_nlsock_close(struct nss_nlsock_ctx *sock)
{
	assert(sock);
	assert(sock->nl_sk);
	assert(sock->ref_cnt > 0);

	/*
	 * put the reference down for the socket
	 */
	nss_nlsock_deref(sock);

	/*
	 * wait for the sync thread to complete
	 */
	if (sock->thread) {
		pthread_join(sock->thread, NULL);
		sock->thread = NULL;
	}
}

/*
 * nss_nlsock_send()
 *	send a message through the socket
 */
int nss_nlsock_send(struct nss_nlsock_ctx *sock, struct nss_nlcmn *cm, void *data)
{
	int pid = sock->pid;
	struct nl_msg *msg;
	void *user_hdr;
	uint32_t ver;
	uint8_t cmd;
	int error;
	int len;

	/*
	 * allocate new message buffer
	 */
	msg = nlmsg_alloc();
	if (!msg) {
		nss_nlsock_log_error("%d:failed to allocate message buffer\n", pid);
		return -ENOMEM;
	}

	ver = nss_nlcmn_get_ver(cm);
	len = nss_nlcmn_get_len(cm);
	cmd = nss_nlcmn_get_cmd(cm);

	/*
	 * create space for user header
	 */
	user_hdr = genlmsg_put(msg, pid, NL_AUTO_SEQ, sock->family_id, len, 0, cmd, ver);
	if (!user_hdr) {
		nss_nlsock_log_error("%d:failed to put message header of len(%d)\n", pid, len);
		nlmsg_free(msg);
		return -ENOMEM;

	}

	memcpy(user_hdr, data, len);

	if (!nss_nlsock_ref(sock)) {
		nss_nlsock_log_error("%d:failed to get NL socket\n", pid);
		nlmsg_free(msg);
		return -EINVAL;
	}

	/*increment the msg reference count */
	nlmsg_get(msg);

	/*
	 * send message and wait for ACK/NACK, this will free message upon success
	 */
	error = nl_send_sync(sock->nl_sk, msg);
	if (error < 0) {
		nss_nlsock_log_error("%d:failed to send (family:%s, error:%d)\n", pid, sock->family_name, error);
		nss_nlsock_deref(sock);
		return error;
	}

	nss_nlsock_deref(sock);
	return 0;
}
