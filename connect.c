#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <termios.h>
#include <pwd.h>
#include <pty.h>
#include <poll.h>
#include <signal.h>
#include <getopt.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <pthread.h>

#include "io.h"
#include "tty.h"

#define DEFAULT_HOST    "127.0.0.1"
#define DEFAULT_PORT    7722
#define DEFAULT_SHELL   "/bin/bash"
#define DRAIN_MS        200

struct connect_hello {
  unsigned short rows;
  unsigned short cols;
};

extern char **environ;

static void daemonize(void)
{
  pid_t pid = fork();
  if (pid < 0)  exit(EXIT_FAILURE);
  if (pid > 0)  exit(EXIT_SUCCESS);
  if (setsid() < 0) exit(EXIT_FAILURE);
  signal(SIGHUP, SIG_IGN);

  int devnull = open("/dev/null", O_RDWR);
  if (devnull >= 0) {
    dup2(devnull, STDIN_FILENO);
    dup2(devnull, STDOUT_FILENO);
    dup2(devnull, STDERR_FILENO);
    if (devnull > STDERR_FILENO)
      close(devnull);
  }
}

/* Returns 1 if "name=..." should be forwarded from the client (LANG, LC_*). */
static int is_locale_var(const char *entry)
{
  if (strncmp(entry, "LANG=", 5) == 0)
    return 1;
  if (strncmp(entry, "LC_", 3) == 0)
    return 1;
  return 0;
}

/* Collect LANG + LC_* entries from environ into a freshly malloc'd blob. */
static char *build_lc_blob(uint32_t *out_size)
{
  size_t total = 0;
  char **e;

  for (e = environ; *e; e++)
    if (is_locale_var(*e))
      total += strlen(*e) + 1;

  *out_size = (uint32_t)total;
  if (total == 0)
    return NULL;

  char *buf = malloc(total);
  if (!buf) return NULL;

  char *p = buf;
  for (e = environ; *e; e++) {
    if (is_locale_var(*e)) {
      size_t len = strlen(*e) + 1;
      memcpy(p, *e, len);
      p += len;
    }
  }
  return buf;
}

/* Apply the client's locale blob into the current process environment. */
static void apply_lc_blob(const char *blob, uint32_t size)
{
  const char *p   = blob;
  const char *end = blob + size;

  while (p < end) {
    size_t remaining = (size_t)(end - p);
    size_t klen = strnlen(p, remaining);

    if (klen == remaining)   /* no NUL terminator: stop */
      break;

    if (is_locale_var(p)) {
      const char *eq = memchr(p, '=', klen);
      if (eq) {
        size_t nlen = (size_t)(eq - p);
        char name[64];
        if (nlen < sizeof(name)) {
          memcpy(name, p, nlen);
          name[nlen] = '\0';
          setenv(name, eq + 1, 1);
        }
      }
    }
    p += klen + 1;
  }
}

static void run_child(const char *lc_blob, uint32_t lc_size, int slave_fd)
{
  struct passwd *pw;
  const char *shell;
  const char *base;
  static char login_argv0[64];
  char *exec_args[2];

  setsid();
  ioctl(slave_fd, TIOCSCTTY, 0);
  dup2(slave_fd, STDIN_FILENO);
  dup2(slave_fd, STDOUT_FILENO);
  dup2(slave_fd, STDERR_FILENO);
  if (slave_fd > STDERR_FILENO)
    close(slave_fd);

  /* Apply the client's locale overrides (LANG, LC_*). */
  if (lc_blob && lc_size > 0)
    apply_lc_blob(lc_blob, lc_size);

  pw = getpwuid(getuid());
  if (pw) {
    setenv("USER",    pw->pw_name, 1);
    setenv("LOGNAME", pw->pw_name, 1);
    setenv("HOME",    pw->pw_dir,  1);
    if (chdir(pw->pw_dir) != 0 && chdir("/") != 0) {
      /* stay wherever we are */
    }
    shell = pw->pw_shell;
    if (!shell || shell[0] == '\0')
      shell = DEFAULT_SHELL;
  } else {
    shell = DEFAULT_SHELL;
  }

  /* login shell: prefix argv[0] with '-' */
  base = strrchr(shell, '/');
  base = base ? base + 1 : shell;
  snprintf(login_argv0, sizeof(login_argv0), "-%s", base);

  exec_args[0] = login_argv0;
  exec_args[1] = NULL;

  execvp(shell, exec_args);

  fprintf(stderr, "connect: %s: %s\n", shell, strerror(errno));
  _exit(126);
}

#define PKT_DATA  1
#define PKT_WINCH 2
#define PKT_EXIT  3

struct pkt_hdr {
  uint8_t  type;
  uint32_t len;
} __attribute__((packed));

struct pkt_winch {
  uint16_t rows;
  uint16_t cols;
} __attribute__((packed));

static int send_pkt(int fd, uint8_t type, const void *payload, uint32_t len)
{
  struct pkt_hdr hdr;
  hdr.type = type;
  hdr.len  = htonl(len);
  if (write_all(fd, &hdr, sizeof(hdr)) != 0)
    return -1;
  if (len > 0 && payload) {
    if (write_all(fd, payload, len) != 0)
      return -1;
  }
  return 0;
}

static int recv_pkt(int fd, uint8_t *type, void *buf, uint32_t max_len, uint32_t *out_len)
{
  struct pkt_hdr hdr;
  if (read_all(fd, &hdr, sizeof(hdr)) != 0)
    return -1;
  *type = hdr.type;
  uint32_t len = ntohl(hdr.len);
  if (len > max_len)
    return -1;
  if (len > 0 && buf) {
    if (read_all(fd, buf, len) != 0)
      return -1;
  }
  *out_len = len;
  return 0;
}

struct session_args {
  int      client_fd;
  int      master_fd;
  pid_t    shell_pid;
};

static void *session_thread(void *arg)
{
  struct session_args *sa = arg;
  int      client_fd = sa->client_fd;
  int      master_fd = sa->master_fd;
  pid_t    shell_pid = sa->shell_pid;
  char     buf[4096];
  struct   pollfd pf[2];
  int      status = -1;
  int      reaped = 0;

  free(sa);

  /* Remove the handshake timeout set before the thread was spawned. */
  {
    struct timeval zero = { 0, 0 };
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));
  }

  /* Relay loop: bridge master_fd <-> client_fd using packets. */
  for (;;) {
    pid_t wp = waitpid(shell_pid, &status, WNOHANG);
    if (wp > 0) {
      reaped = 1;
      break;
    }

    pf[0].fd      = master_fd;
    pf[0].events  = POLLIN;
    pf[0].revents = 0;
    pf[1].fd      = client_fd;
    pf[1].events  = POLLIN;
    pf[1].revents = 0;

    if (poll(pf, 2, -1) < 0) {
      if (errno == EINTR) continue;
      break;
    }

    /* Master pty output -> send as PKT_DATA to client */
    if (pf[0].revents & POLLIN) {
      ssize_t n = read(master_fd, buf, sizeof(buf));
      if (n <= 0) break;
      if (send_pkt(client_fd, PKT_DATA, buf, (uint32_t)n) != 0) break;
    }

    /* Packet from client -> process data or window resize */
    if (pf[1].revents & POLLIN) {
      uint8_t type;
      uint32_t len;
      if (recv_pkt(client_fd, &type, buf, sizeof(buf), &len) != 0) break;

      if (type == PKT_DATA && len > 0) {
        if (write_all(master_fd, buf, len) != 0) break;
      } else if (type == PKT_WINCH && len == sizeof(struct pkt_winch)) {
        struct pkt_winch *w = (struct pkt_winch *)buf;
        struct winsize ws;
        memset(&ws, 0, sizeof(ws));
        ws.ws_row = ntohs(w->rows);
        ws.ws_col = ntohs(w->cols);
        ioctl(master_fd, TIOCSWINSZ, &ws);
      }
    }

    if (pf[0].revents & (POLLHUP | POLLERR)) break;
    if (pf[1].revents & (POLLHUP | POLLERR)) break;
  }

  if (!reaped) {
    kill(shell_pid, SIGHUP);
    if (waitpid(shell_pid, &status, 0) < 0)
      status = -1;
  }

  int32_t net_status = htonl((int32_t)status);
  send_pkt(client_fd, PKT_EXIT, &net_status, sizeof(net_status));

  close(master_fd);
  close(client_fd);
  return NULL;
}

static void handle_connection(int server_fd)
{
  struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
  struct connect_hello hello;
  uint32_t lc_size = 0;
  char *lc_blob = NULL;
  int master_fd, slave_fd;
  struct winsize ws;
  uint8_t ok;
  pid_t shell_pid;
  struct session_args *sa;
  pthread_t tid;
  pthread_attr_t attr;

  int client_fd = accept(server_fd, NULL, NULL);
  if (client_fd < 0)
    return;

  /* Enable TCP keepalive so we notice dead clients. */
  {
    int val = 1;
    setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
#ifdef TCP_KEEPIDLE
    val = 60;
    setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val));
#endif
  }

  /* A stalled client must not block the accept loop. */
  setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  if (read_all(client_fd, &hello, sizeof(hello)) != 0 ||
      read_all(client_fd, &lc_size, sizeof(lc_size)) != 0 ||
      lc_size > (1u << 16)) {
    close(client_fd);
    return;
  }

  if (lc_size > 0) {
    lc_blob = malloc(lc_size);
    if (!lc_blob || read_all(client_fd, lc_blob, lc_size) != 0) {
      free(lc_blob);
      close(client_fd);
      return;
    }
  }

  ws.ws_row    = hello.rows ? hello.rows : 24;
  ws.ws_col    = hello.cols ? hello.cols : 80;
  ws.ws_xpixel = 0;
  ws.ws_ypixel = 0;

  if (openpty(&master_fd, &slave_fd, NULL, NULL, &ws) != 0) {
    free(lc_blob);
    close(client_fd);
    return;
  }

  shell_pid = fork();
  if (shell_pid == 0) {
    close(client_fd);
    close(master_fd);
    run_child(lc_blob, lc_size, slave_fd);
    /* run_child never returns */
  }

  close(slave_fd);
  free(lc_blob);

  if (shell_pid < 0) {
    ok = 0;
    write_all(client_fd, &ok, sizeof(ok));
    close(master_fd);
    close(client_fd);
    return;
  }

  /* Tell the client the shell is ready. */
  ok = 1;
  if (write_all(client_fd, &ok, sizeof(ok)) != 0) {
    kill(shell_pid, SIGKILL);
    close(master_fd);
    close(client_fd);
    return;
  }

  /* Hand off to a detached relay thread. */
  sa = malloc(sizeof(*sa));
  if (!sa) {
    kill(shell_pid, SIGKILL);
    close(master_fd);
    close(client_fd);
    return;
  }
  sa->client_fd = client_fd;
  sa->master_fd = master_fd;
  sa->shell_pid = shell_pid;

  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  if (pthread_create(&tid, &attr, session_thread, sa) != 0) {
    free(sa);
    kill(shell_pid, SIGKILL);
    waitpid(shell_pid, NULL, WNOHANG);
    close(master_fd);
    close(client_fd);
    pthread_attr_destroy(&attr);
    return;
  }
  pthread_attr_destroy(&attr);
}

static void run_server(const char *host, int port, int foreground)
{
  int server_fd;
  struct sockaddr_in addr;
  int opt;

  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    perror("connect: socket");
    exit(EXIT_FAILURE);
  }
  opt = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port   = htons((uint16_t)port);
  if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
    struct hostent *he = gethostbyname(host);
    if (!he) {
      fprintf(stderr, "connect: cannot resolve %s\n", host);
      exit(EXIT_FAILURE);
    }
    memcpy(&addr.sin_addr, he->h_addr_list[0], sizeof(addr.sin_addr));
  }

  if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("connect: bind");
    exit(EXIT_FAILURE);
  }
  if (listen(server_fd, 16) < 0) {
    perror("connect: listen");
    exit(EXIT_FAILURE);
  }

  fprintf(stderr, "connect: listening on %s:%d (uid %d)\n",
          host, port, (int)getuid());

  if (!foreground)
    daemonize();

  signal(SIGPIPE, SIG_IGN);

  for (;;) {
    struct pollfd pfd;
    pfd.fd     = server_fd;
    pfd.events = POLLIN;

    int pr = poll(&pfd, 1, -1);
    if (pr < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (pfd.revents & POLLIN)
      handle_connection(server_fd);
  }

  close(server_fd);
  exit(0);
}

static int run_client_loop(int sock_fd)
{
  struct pollfd fds[2];
  char buf[4096];
  int raw_status  = -1;
  int stdin_open  = 1;
  int sock_open   = 1;
  int stdin_tty   = isatty(STDIN_FILENO);

  raw_mode_enter();
  winch_install();

  for (;;) {
    if (winch_pending) {
      winch_pending = 0;
      struct winsize ws;
      if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
        struct pkt_winch w;
        w.rows = htons(ws.ws_row);
        w.cols = htons(ws.ws_col);
        send_pkt(sock_fd, PKT_WINCH, &w, sizeof(w));
      }
    }

    if (!sock_open)
      break;

    fds[0].fd      = stdin_open ? STDIN_FILENO : -1;
    fds[0].events  = POLLIN;
    fds[0].revents = 0;
    fds[1].fd      = sock_open ? sock_fd : -1;
    fds[1].events  = POLLIN;
    fds[1].revents = 0;

    int r = poll(fds, 2, -1);
    if (r < 0) {
      if (errno == EINTR) continue;
      break;
    }

    /* Packet from server -> check type */
    if (fds[1].revents & POLLIN) {
      uint8_t type;
      uint32_t len;
      if (recv_pkt(sock_fd, &type, buf, sizeof(buf), &len) != 0) {
        sock_open = 0;
      } else {
        if (type == PKT_DATA && len > 0) {
          if (write_all(STDOUT_FILENO, buf, len) != 0)
            sock_open = 0;
        } else if (type == PKT_EXIT && len == sizeof(int32_t)) {
          int32_t net_status;
          memcpy(&net_status, buf, sizeof(net_status));
          raw_status = (int)ntohl(net_status);
          sock_open = 0;
        }
      }
    }

    /* Local stdin -> send as PKT_DATA */
    if (fds[0].revents & POLLIN) {
      ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
      if (n < 0 && errno == EINTR)
        continue;
      if (n <= 0) {
        stdin_open = 0;
        if (!stdin_tty) {
          char eof_char = 004;
          send_pkt(sock_fd, PKT_DATA, &eof_char, 1);
        } else {
          sock_open = 0;
          shutdown(sock_fd, SHUT_WR);
        }
      } else {
        if (send_pkt(sock_fd, PKT_DATA, buf, (uint32_t)n) != 0)
          stdin_open = 0;
      }
    }
  }

  close(sock_fd);
  raw_mode_leave();

  if (raw_status != -1) {
    if (WIFSIGNALED(raw_status))
      return 128 + WTERMSIG(raw_status);
    if (WIFEXITED(raw_status))
      return WEXITSTATUS(raw_status);
  }
  return 1;
}

static int connect_to_server(const char *host, int port)
{
  struct sockaddr_in addr;
  int fd;

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port   = htons((uint16_t)port);

  if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
    struct hostent *he = gethostbyname(host);
    if (!he) {
      close(fd);
      return -1;
    }
    memcpy(&addr.sin_addr, he->h_addr_list[0], sizeof(addr.sin_addr));
  }

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }

  return fd;
}

static void usage(const char *prog)
{
  fprintf(stderr,
    "Usage:\n"
    "  %s --server [--host ADDR] [--port PORT] [--foreground]\n"
    "  %s [--host HOST] [--port PORT]\n"
    "\n"
    "Defaults: host=%s, port=%d\n"
    "\n"
    "The server runs as the current user.  Every connecting client receives\n"
    "a login shell (sudo -i equivalent) with the server's environment.\n"
    "Only LANG and LC_* are forwarded from the client.\n",
    prog, prog, DEFAULT_HOST, DEFAULT_PORT);
}

int main(int argc, char *argv[])
{
  static const struct option long_opts[] = {
    { "server",     no_argument,       NULL, 'S' },
    { "host",       required_argument, NULL, 'H' },
    { "port",       required_argument, NULL, 'p' },
    { "foreground", no_argument,       NULL, 'f' },
    { "help",       no_argument,       NULL, 'h' },
    { NULL, 0, NULL, 0 }
  };

  const char *host   = DEFAULT_HOST;
  int         port   = DEFAULT_PORT;
  int         server = 0;
  int         fg     = 0;
  int         opt;


  while ((opt = getopt_long(argc, argv, "+SH:p:fh", long_opts, NULL)) != -1) {
    switch (opt) {
    case 'S': server = 1;              break;
    case 'H': host   = optarg;         break;
    case 'p':
      port = atoi(optarg);
      if (port <= 0 || port > 65535) {
        fprintf(stderr, "connect: invalid port: %s\n", optarg);
        return 1;
      }
      break;
    case 'f': fg = 1;                  break;
    case 'h': usage(argv[0]);          return 0;
    default:  usage(argv[0]);          return 1;
    }
  }

  if (optind < argc) {
    fprintf(stderr, "connect: unexpected argument: %s\n", argv[optind]);
    usage(argv[0]);
    return 1;
  }

  if (server) {
    run_server(host, port, fg);
    return 0;
  }

  int sock_fd = connect_to_server(host, port);
  if (sock_fd < 0) {
    fprintf(stderr, "connect: cannot connect to %s:%d: %s\n",
            host, port, strerror(errno));
    return 1;
  }

  /* Set a generous receive timeout so a dead server does not hang us. */
  {
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  }

  /* Send the greeting: terminal size + locale blob. */
  struct connect_hello hello;
  memset(&hello, 0, sizeof(hello));
  {
    struct winsize ws;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
      hello.rows = ws.ws_row;
      hello.cols = ws.ws_col;
    } else {
      hello.rows = 24;
      hello.cols = 80;
    }
  }

  if (write_all(sock_fd, &hello, sizeof(hello)) != 0) {
    fprintf(stderr, "connect: failed to send greeting\n");
    close(sock_fd);
    return 1;
  }

  uint32_t lc_size = 0;
  char *lc_blob = build_lc_blob(&lc_size);

  if (write_all(sock_fd, &lc_size, sizeof(lc_size)) != 0) {
    fprintf(stderr, "connect: failed to send locale size\n");
    free(lc_blob);
    close(sock_fd);
    return 1;
  }
  if (lc_size > 0 && write_all(sock_fd, lc_blob, lc_size) != 0) {
    fprintf(stderr, "connect: failed to send locale blob\n");
    free(lc_blob);
    close(sock_fd);
    return 1;
  }
  free(lc_blob);

  /* Wait for the server's "ready" byte. */
  {
    uint8_t ok = 0;
    if (read_all(sock_fd, &ok, sizeof(ok)) != 0 || ok != 1) {
      fprintf(stderr, "connect: server rejected the connection\n");
      close(sock_fd);
      return 1;
    }
  }

  /* Remove the receive timeout: interactive sessions may be idle a while.
     Keepalive handles dead connections instead. */
  {
    struct timeval tv = { .tv_sec = 0, .tv_usec = 0 };
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int val = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
#ifdef TCP_KEEPIDLE
    val = 60;
    setsockopt(sock_fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val));
#endif
  }

  return run_client_loop(sock_fd);
}
