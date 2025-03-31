#include <linux/android/binder_netlink.h>
#include <linux/genetlink.h>
#include <sys/socket.h>

#include "binder_common.h"

#define BINDER_MSG_SIZE 1024

#define GENLMSG_DATA(glh) ((void*)((char*)(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(nlh) (NLMSG_PAYLOAD(nlh, 0) - GENL_HDRLEN)
#define NLA_DATA(nla) ((void*)((char*)(nla) + NLA_HDRLEN))
#define NLA_NEXT(nla) ((struct nlattr*)((char*)nla + NLA_ALIGN(nla->nla_len)))

struct genlmsg {
    struct nlmsghdr nlh;
    union {
        struct genlmsghdr glh;
        int error;
    };
    char buf[BINDER_MSG_SIZE];
};

static void usage(char *progname)
{
	fprintf(stderr,
		"usage:  %s [-n] [-v]\n"
		"Where:\n\t"
		"-n  Use the /dev/binderfs name service.\n\t"
		"-v  Print context and command information.\n\t"
		"\nNote: Ensure this boolean command is run when "
		"testing after a reboot:\n\t"
		"setsebool allow_domain_fd_use=0\n", progname);
	exit(-1);
}

static int sendgenl(int fd, __u32 pid, __u16 nlmsg_type, __u8 cmd, __u16 nla_type,
		const void* nla_data, __u16 nla_len)
{
	if (NLA_ALIGN(nla_len) + NLA_HDRLEN > BINDER_MSG_SIZE) {
		fprintf(stderr, "Oversized data to send\n");
		return -ENOMEM;
	}

	struct genlmsg msg = {
		.nlh = {
				.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN),
				.nlmsg_type = nlmsg_type,
				.nlmsg_flags = NLM_F_REQUEST,
				.nlmsg_seq = 0,
				.nlmsg_pid = pid,
		},
		.glh = {
			.cmd = cmd,
			.version = BINDER_FAMILY_VERSION,
		},
	};

	struct nlattr* nla = GENLMSG_DATA(&msg.glh);
	nla->nla_type = nla_type;
	nla->nla_len = nla_len + NLA_HDRLEN;
	memcpy(NLA_DATA(nla), nla_data, nla_len);
	msg.nlh.nlmsg_len += NLA_ALIGN(nla->nla_len);

	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
	};
	int ret = sendto(fd, &msg, msg.nlh.nlmsg_len, 0, (struct sockaddr*)&sa, sizeof(sa));
	if (ret < 0)
		fprintf(stderr, "Failed to send (%d %d %d %d): %s\n",
				nlmsg_type, cmd, nla_type, nla_len, strerror(errno));

	if (verbose)
		printf("Sent %d / %d bytes to binder netlink\n", ret, msg.nlh.nlmsg_len);

	return ret;
}

static int sendgenlv(int fd, __u32 pid, __u16 nlmsg_type, __u8 cmd, __u16 nla_type[],
		const void* nla_data[], __u16 nla_len[], int n)
{
	__u32 len = 0;
	for (int i = 0; i < n; i++)
		len += NLA_ALIGN(nla_len[i]) + NLA_HDRLEN;

	if (len > BINDER_MSG_SIZE) {
		fprintf(stderr, "Oversized data to send: %d > %d\n", len, BINDER_MSG_SIZE);
		return -ENOMEM;
	}

	struct genlmsg msg = {
		.nlh = {
				.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN),
				.nlmsg_type = nlmsg_type,
				.nlmsg_flags = NLM_F_REQUEST,
				.nlmsg_seq = 0,
				.nlmsg_pid = pid,
		},
		.glh = {
			.cmd = cmd,
			.version = BINDER_FAMILY_VERSION,
		},
	};

	struct nlattr* nla = GENLMSG_DATA(&msg.glh);
	for (int i = 0; i < n; i++) {
		nla->nla_type = nla_type[i];
		nla->nla_len = nla_len[i] + NLA_HDRLEN;
		memcpy(NLA_DATA(nla), nla_data[i], nla_len[i]);
		nla = (struct nlattr*)((char*)(nla) + NLA_ALIGN(nla->nla_len));
	}
	msg.nlh.nlmsg_len += len;

	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
	};

	int ret = sendto(fd, &msg, msg.nlh.nlmsg_len, 0, (struct sockaddr*)&sa, sizeof(sa));
	if (ret < 0) {
		fprintf(stderr, "Failed to send (%d %d %d): %s\n",
				nlmsg_type, cmd, n, strerror(errno));
	}

	if (verbose)
		printf("Sent %d / %d bytes\n", ret, msg.nlh.nlmsg_len);

	return ret;
}

static int recvgenl(int fd, struct genlmsg* msg, int len)
{
	int ret = recv(fd, msg, len, 0);
	if (verbose) {
		printf("Received %d\n", ret);
		printf("nlh: %d %d %d %d %d\n", msg->nlh.nlmsg_len, msg->nlh.nlmsg_type,
				msg->nlh.nlmsg_flags, msg->nlh.nlmsg_seq, msg->nlh.nlmsg_pid);
	}

	if (ret < 0) {
		fprintf(stderr, "Failed to receive %d: %s\n", ret, strerror(errno));
		return ret;
	} else if (msg->nlh.nlmsg_type == NLMSG_ERROR) {
		ret = msg->error;
		fprintf(stderr, "Error msg received %d: %s\n", ret, strerror(-ret));
		return ret;
	} else if (!NLMSG_OK(&msg->nlh, ret)) {
		fprintf(stderr, "Wrong message data\n");
		return -EFAULT;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int fd, opt;
	pid_t pid;
	char *context;
	char *name;
	__u16 id = 0;

	while ((opt = getopt(argc, argv, "v")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		default:
			usage(argv[0]);
		}
	}

	/* Get our context and pid */
	if (getcon(&context) < 0) {
		fprintf(stderr, "Failed to obtain SELinux context\n");
		exit(-1);
	}
	pid = getpid();

	if (verbose) {
		fprintf(stderr, "Setup report PID: %d Process context %s\n", pid, context);
	}

	free(context);

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0) {
		fprintf(stderr, "Failed to open socket: %s\n", strerror(errno));
		exit(151);
	}

	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK, .nl_pid = pid,
	};

	if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
		fprintf(stderr, "Failed to bind socket: %s\n", strerror(errno));
		exit(152);
	}

	if (sendgenl(fd, pid, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, CTRL_ATTR_FAMILY_NAME, BINDER_FAMILY_NAME, strlen(BINDER_FAMILY_NAME) + 1) < 0) {
		fprintf(stderr, "Failed to send CTRL_CMD_GETFAMILY\n");
		exit(153);
	}

	struct genlmsg msg;
	if (recvgenl(fd, &msg, sizeof(msg)) < 0) {
		fprintf(stderr, "Failed to receive reply of CTRL_CMD_GETFAMILY\n");
		exit(154);
	}

	if (msg.glh.cmd != CTRL_CMD_NEWFAMILY) {
		fprintf(stderr, "Wrong glh cmd %d, expect %d\n", msg.glh.cmd, CTRL_CMD_NEWFAMILY);
		exit(155);
	}

	int cur = 0;
	int payload = GENLMSG_PAYLOAD(&msg.nlh);
	char* data = GENLMSG_DATA(&msg.glh);
	while (cur < payload) {
		if (verbose)
			printf("Checking NLA payload %d / %d\n", cur, payload);
		struct nlattr* nla = (struct nlattr*)(data + cur);
		if (verbose)
			printf("NLA type / len: %d / %d\n", nla->nla_type, nla->nla_len);
		cur += NLA_ALIGN(nla->nla_len);
		switch (nla->nla_type) {
		case CTRL_ATTR_FAMILY_NAME:
			name = NLA_DATA(nla);
			if (verbose)
				printf("Binder Netlink family name is %s\n", name);
			break;
		case CTRL_ATTR_FAMILY_ID:
			id = *(__u16*)(NLA_DATA(nla));
			if (verbose)
				printf("Binder Netlink family id is %d\n", id);
			break;
		case CTRL_ATTR_MCAST_GROUPS:
			if (verbose)
				printf("Binder Netlink MCAST_GROUP ignored\n");
			break;
		default:
			break;
		}
	}

	if (!id) {
		fprintf(stderr, "Failed to get binder netlink family id\n");
		exit(156);
	}

	__u32 proc = 0;
	__u32 flags = 0;
	__u16 type[3] = { BINDER_A_CMD_CONTEXT, BINDER_A_CMD_PID, BINDER_A_CMD_FLAGS };
	__u16 len[3] = { strlen(BINDERFS_NAME) + 1, sizeof(proc), sizeof(flags) };
	const void* buf[3] = { (void*)BINDERFS_NAME, (void*)&proc, (void*)&flags };

	if (verbose)
		printf("Sending BINDER_CMD_REPORT_SETUP %s %d %d\n", BINDERFS_NAME, proc, flags);

	if (sendgenlv(fd, pid, id, BINDER_CMD_REPORT_SETUP, type, buf, len, 3) < 0) {
		fprintf(stderr, "Failed to send BINDER_CMD_REPORT_SETUP\n");
		exit(157);
	}

	if (recvgenl(fd, &msg, sizeof(msg)) < 0) {
		fprintf(stderr, "Failed to receive reply of BINDER_CMD_REPORT_SETUP\n");
		exit(158);
	}

	if (msg.glh.cmd != BINDER_CMD_REPORT_SETUP) {
		fprintf(stderr, "Wrong glh cmd %d, expect %d\n", msg.glh.cmd, BINDER_CMD_REPORT_SETUP);
		exit(159);
	}

	close(fd);

	return 0;
}
