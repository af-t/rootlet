#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <linux/loop.h>

#define DEFAULT_MOUNT "/mnt/ubuntu"
#define DEFAULT_SU "/usr/bin/su"
#define TERM_GRACE_SECONDS 3
#define MAX_BINDS 64

/* An extra host path to bind into the chroot. "guest" is the absolute path
   inside the tree; when the "-b host" form omits it, it equals "host". */
struct bind {
  const char *host;
  const char *guest;
};

static char distro_path[PATH_MAX];
static char chroot_path[PATH_MAX];
static size_t chroot_len;
static const char *su_path = DEFAULT_SU;
static struct bind binds[MAX_BINDS];
static size_t bind_count;
static char loop_node[32];
static int loop_fd = -1;
static int debug_enabled;

/* Build "<chroot_path><sub>" into one of a few rotating buffers, so a single
   expression can safely hold more than one result at a time. */
static const char *cp(const char *sub)
{
  static char bufs[4][PATH_MAX];
  static unsigned turn;
  char *buf = bufs[turn++ % (sizeof(bufs) / sizeof(bufs[0]))];

  snprintf(buf, PATH_MAX, "%s%s", chroot_path, sub);
  return buf;
}

static void dbg(const char *fmt, ...)
{
  va_list ap;

  if (!debug_enabled)
    return;

  fputs("[rootlet] ", stderr);
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

static void die(const char *what)
{
  fprintf(stderr, "%s: %s\n", what, strerror(errno));
  exit(1);
}

static int mkdir_p(const char *path)
{
  char buf[PATH_MAX];
  char *p;

  if ((size_t)snprintf(buf, sizeof(buf), "%s", path) >= sizeof(buf)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  for (p = buf + 1; *p; p++) {
    if (*p != '/')
      continue;
    *p = '\0';
    if (mkdir(buf, 0755) != 0 && errno != EEXIST)
      return -1;
    *p = '/';
  }

  if (mkdir(buf, 0755) != 0 && errno != EEXIST)
    return -1;

  return 0;
}

/* Android keeps block nodes under /dev/block, and ueventd can create a
   freshly allocated one slightly after LOOP_CTL_GET_FREE returns. */
static int open_loop_node(int number)
{
  static const char *const dirs[] = { "/dev/block", "/dev" };
  struct timespec delay = { 0, 100 * 1000 * 1000 };
  int attempt;
  size_t i;

  for (attempt = 0; attempt < 5; attempt++) {
    for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
      int fd;

      snprintf(loop_node, sizeof(loop_node), "%s/loop%d",
         dirs[i], number);

      fd = open(loop_node, O_RDWR | O_CLOEXEC);
      if (fd >= 0)
        return fd;

      dbg("open %s: %s", loop_node, strerror(errno));
      if (errno != ENOENT)
        return -1;
    }

    nanosleep(&delay, NULL);
  }

  snprintf(loop_node, sizeof(loop_node), "loop%d", number);
  errno = ENOENT;
  return -1;
}

static void loop_attach(void)
{
  struct loop_info64 info;
  size_t name_len;
  int ctl, img, attempt;

  ctl = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
  if (ctl < 0)
    die("open /dev/loop-control");

  img = open(distro_path, O_RDWR | O_CLOEXEC);
  if (img < 0)
    die(distro_path);

  /* LOOP_CTL_GET_FREE only reserves a number, so a racing attach can
     still take it before LOOP_SET_FD lands. */
  for (attempt = 0; attempt < 16; attempt++) {
    int node;

    node = ioctl(ctl, LOOP_CTL_GET_FREE);
    if (node < 0)
      die("LOOP_CTL_GET_FREE");

    dbg("LOOP_CTL_GET_FREE -> %d", node);

    loop_fd = open_loop_node(node);
    if (loop_fd < 0) {
      fprintf(stderr, "%s: %s (tried /dev/block and /dev)\n",
        loop_node, strerror(errno));
      exit(1);
    }

    if (ioctl(loop_fd, LOOP_SET_FD, img) == 0)
      break;

    dbg("LOOP_SET_FD %s: %s", loop_node, strerror(errno));
    if (errno != EBUSY)
      die("LOOP_SET_FD");

    close(loop_fd);
    loop_fd = -1;
  }

  close(img);
  close(ctl);

  if (loop_fd < 0) {
    fprintf(stderr, "no free loop device\n");
    exit(1);
  }

  dbg("attached %s -> %s", loop_node, distro_path);

  /* Cosmetic: makes `losetup -l` show the backing file. The field is
     fixed at LO_NAME_SIZE, so a longer path is simply truncated. */
  memset(&info, 0, sizeof(info));
  name_len = strlen(distro_path);
  if (name_len >= sizeof(info.lo_file_name))
    name_len = sizeof(info.lo_file_name) - 1;
  memcpy(info.lo_file_name, distro_path, name_len);
  ioctl(loop_fd, LOOP_SET_STATUS64, &info);
}

static void loop_detach(void)
{
  if (loop_fd < 0)
    return;

  if (ioctl(loop_fd, LOOP_CLR_FD, 0) != 0)
    fprintf(stderr, "detach %s: %s\n", loop_node, strerror(errno));
  else
    dbg("detached %s", loop_node);

  close(loop_fd);
  loop_fd = -1;
}

static int try_mount_rootfs(const char *type)
{
  if (mount(loop_node, chroot_path, type, 0, NULL) == 0) {
    dbg("mounted %s on %s as %s", loop_node, chroot_path, type);
    return 1;
  }

  dbg("try %s: %s", type, strerror(errno));

  /* Anything else means the filesystem matched but the mount is not
     possible, so probing further types is pointless. */
  if (errno != EINVAL && errno != ENODEV && errno != ENXIO)
    die("mount rootfs");

  return 0;
}

/* mount(2) has no type autodetection, so replay what mount(8) would probe. */
static void mount_rootfs(void)
{
  static const char *const preferred[] = { "ext4", "ext3", "ext2", "f2fs" };
  char line[128];
  size_t i;
  FILE *fp;

  for (i = 0; i < sizeof(preferred) / sizeof(preferred[0]); i++)
    if (try_mount_rootfs(preferred[i]))
      return;

  fp = fopen("/proc/filesystems", "r");
  if (fp) {
    while (fgets(line, sizeof(line), fp)) {
      char *type = line;
      char *end;

      if (strncmp(type, "nodev", 5) == 0)
        continue;

      type += strspn(type, " \t");
      end = type + strcspn(type, " \t\r\n");
      *end = '\0';
      if (*type == '\0')
        continue;

      for (i = 0; i < sizeof(preferred) / sizeof(preferred[0]); i++)
        if (strcmp(type, preferred[i]) == 0)
          break;
      if (i < sizeof(preferred) / sizeof(preferred[0]))
        continue;

      if (try_mount_rootfs(type)) {
        fclose(fp);
        return;
      }
    }
    fclose(fp);
  }

  fprintf(stderr, "mount rootfs failed: unrecognized filesystem\n");
  loop_detach();
  exit(1);
}

static void mount_soft(const char *source, const char *target,
           const char *type, unsigned long flags, const char *data)
{
  if (mount(source, target, type, flags, data) != 0)
    fprintf(stderr, "mount %s: %s\n", target, strerror(errno));
  else
    dbg("mount ok: %s", target);
}

/* Debug-only survey of what the image actually contains, which is the
   information needed when the session binary fails to exec. */
static void probe_rootfs(void)
{
  struct dirent *ent;
  struct stat st;
  const char *inst;
  const char *alt;
  int shown = 0;
  DIR *dir;

  if (!debug_enabled)
    return;

  dir = opendir(chroot_path);
  if (!dir) {
    dbg("opendir %s: %s", chroot_path, strerror(errno));
    return;
  }

  while ((ent = readdir(dir)) != NULL && shown < 64) {
    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
      continue;
    dbg("  rootfs: %s", ent->d_name);
    shown++;
  }
  closedir(dir);

  inst = cp(su_path);
  if (stat(inst, &st) == 0)
    dbg("%s: mode=%04o size=%lld", inst,
        (unsigned)(st.st_mode & 07777), (long long)st.st_size);
  else
    dbg("%s: %s", inst, strerror(errno));

  alt = cp("/bin/su");
  if (stat(alt, &st) == 0)
    dbg("%s: mode=%04o size=%lld", alt,
        (unsigned)(st.st_mode & 07777), (long long)st.st_size);
  else
    dbg("%s: %s", alt, strerror(errno));
}

/* User-requested binds from -b, applied after the fixed ones. The target
   directory is created first so a bind onto a path the image lacks still
   works, mirroring how /mnt/sdcard is handled. */
static void mount_binds(void)
{
  size_t i;

  for (i = 0; i < bind_count; i++) {
    const char *target = cp(binds[i].guest);

    if (mkdir_p(target) != 0) {
      fprintf(stderr, "mkdir %s: %s\n", target, strerror(errno));
      continue;
    }
    mount_soft(binds[i].host, target, NULL, MS_BIND, NULL);
  }
}

static void do_mount(void)
{
  const char *sdcard;

  loop_attach();

  if (mkdir_p(chroot_path) != 0)
    die(chroot_path);

  mount_rootfs();

  mount_soft("/sys", cp("/sys"), NULL, MS_BIND, NULL);
  mount_soft("/dev", cp("/dev"), NULL, MS_BIND, NULL);
  mount_soft("/dev/pts", cp("/dev/pts"), NULL, MS_BIND, NULL);
  mount_soft("proc", cp("/proc"), "proc", 0, NULL);
  mount_soft("tmpfs", cp("/mnt"), "tmpfs", 0, "size=20%,mode=0755");
  mount_soft("tmpfs", cp("/tmp"), "tmpfs", 0, "size=50%,mode=1777");

  sdcard = cp("/mnt/sdcard");
  if (mkdir_p(sdcard) != 0)
    fprintf(stderr, "mkdir %s: %s\n", sdcard, strerror(errno));
  else
    mount_soft("/sdcard", sdcard, NULL, MS_BIND, NULL);

  mount_binds();

  probe_rootfs();
}

static void umount_soft(const char *target)
{
  if (umount2(target, 0) != 0)
    fprintf(stderr, "umount %s: %s\n", target, strerror(errno));
  else
    dbg("umount ok: %s", target);
}

static void umount_mnt_entries(void)
{
  char path[PATH_MAX];
  struct dirent *ent;
  DIR *dir;

  dir = opendir(cp("/mnt"));
  if (!dir)
    return;

  while ((ent = readdir(dir)) != NULL) {
    int n;

    if (ent->d_name[0] == '.')
      continue;
    n = snprintf(path, sizeof(path), "%s/mnt/%s", chroot_path,
           ent->d_name);
    if (n < 0 || (size_t)n >= sizeof(path))
      continue;
    if (umount2(path, 0) == 0)
      dbg("umount ok: %s", path);
  }

  closedir(dir);
}

static void umount_binds(void)
{
  size_t i;

  for (i = bind_count; i-- > 0; )
    umount_soft(cp(binds[i].guest));
}

static void do_umount(void)
{
  umount_binds();

  umount_mnt_entries();

  umount_soft(cp("/dev/pts"));
  umount_soft(cp("/dev"));
  umount_soft(cp("/sys"));
  umount_soft(cp("/proc"));
  umount_soft(cp("/mnt"));
  umount_soft(cp("/tmp"));

  umount_soft(chroot_path);

  loop_detach();

  rmdir(chroot_path);
}

static int path_in_chroot(const char *path)
{
  /* Require a boundary after the prefix so the mount point does not also
     match a sibling like "/mnt/ubuntu-backup". */
  return strncmp(path, chroot_path, chroot_len) == 0 &&
         (path[chroot_len] == '/' || path[chroot_len] == '\0');
}

/* A process belongs to the session when its executable, root or working
   directory lives inside the chroot, or when it merely keeps a descriptor
   open there. The root/cwd/fd checks catch helpers exec'd from outside the
   tree (or whose backing file was already unlinked) that would still pin
   the mount and block umount. On a match, "match" holds the path that
   matched, for logging. */
static int belongs_to_chroot(pid_t pid, char *match, size_t match_size)
{
  static const char *const links[] = { "exe", "root", "cwd" };
  char path[64];
  struct dirent *ent;
  ssize_t len;
  DIR *dir;
  size_t i;

  for (i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
    snprintf(path, sizeof(path), "/proc/%d/%s", (int)pid, links[i]);
    len = readlink(path, match, match_size - 1);
    if (len < 0)
      continue;
    match[len] = '\0';
    if (path_in_chroot(match))
      return 1;
  }

  snprintf(path, sizeof(path), "/proc/%d/fd", (int)pid);
  dir = opendir(path);
  if (!dir)
    return 0;

  while ((ent = readdir(dir)) != NULL) {
    if (ent->d_name[0] == '.')
      continue;

    len = readlinkat(dirfd(dir), ent->d_name, match, match_size - 1);
    if (len < 0)
      continue;
    match[len] = '\0';

    if (path_in_chroot(match)) {
      closedir(dir);
      return 1;
    }
  }

  closedir(dir);
  return 0;
}

/* The shell version forked one subshell per PID just to serialize
   kill/sleep/kill; signalling every match first collapses that into a
   single grace period. */
static void kill_chroot_processes(void)
{
  struct timespec grace = { TERM_GRACE_SECONDS, 0 };
  char match[PATH_MAX];
  pid_t self = getpid();
  pid_t *killed = NULL;
  size_t count = 0, cap = 0;
  struct dirent *ent;
  DIR *dir;

  dir = opendir("/proc");
  if (!dir)
    return;

  while ((ent = readdir(dir)) != NULL) {
    char *end;
    long pid;

    pid = strtol(ent->d_name, &end, 10);
    if (*end != '\0' || pid <= 0 || (pid_t)pid == self)
      continue;

    if (!belongs_to_chroot((pid_t)pid, match, sizeof(match)))
      continue;

    if (kill((pid_t)pid, SIGTERM) != 0)
      continue;

    dbg("SIGTERM %ld (%s)", pid, match);

    if (count == cap) {
      size_t next = cap ? cap * 2 : 64;
      pid_t *grown = realloc(killed, next * sizeof(*killed));

      if (!grown)
        continue;

      killed = grown;
      cap = next;
    }

    killed[count++] = (pid_t)pid;
  }

  closedir(dir);
  dbg("chroot processes signalled: %zu", count);

  if (count == 0) {
    free(killed);
    return;
  }

  while (nanosleep(&grace, &grace) != 0 && errno == EINTR)
    ;

  /* Re-check membership so a recycled PID is not hit with SIGKILL. */
  for (size_t i = 0; i < count; i++) {
    if (kill(killed[i], 0) != 0)
      continue;
    if (!belongs_to_chroot(killed[i], match, sizeof(match)))
      continue;

    kill(killed[i], SIGKILL);
    dbg("SIGKILL %d (%s)", (int)killed[i], match);
  }

  free(killed);
}

static struct termios saved_termios;
static int termios_saved;
static volatile sig_atomic_t winch_pending;

static void on_winch(int sig)
{
  (void)sig;
  winch_pending = 1;
}

static void push_window_size(int master)
{
  struct winsize ws;

  if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
    ioctl(master, TIOCSWINSZ, &ws);
}

static void open_pty(int *master, int *slave)
{
  char name[PATH_MAX];
  int fd;

  fd = posix_openpt(O_RDWR | O_NOCTTY);
  if (fd < 0)
    die("posix_openpt");
  if (grantpt(fd) != 0 || unlockpt(fd) != 0)
    die("unlockpt");
  if (ptsname_r(fd, name, sizeof(name)) != 0)
    die("ptsname_r");

  /* Opened before the chroot: the descriptor survives the root change,
     while the /dev/pts path need not resolve the same way afterwards. */
  *slave = open(name, O_RDWR | O_NOCTTY);
  if (*slave < 0)
    die(name);

  push_window_size(fd);
  dbg("session tty: %s", name);

  *master = fd;
}

/* Give the session its own controlling terminal, so job control, ^C and
   ^Z belong to the inner shell instead of being shared with the caller. */
static void attach_pty(int slave)
{
  if (setsid() < 0) {
    fprintf(stderr, "setsid: %s\n", strerror(errno));
    _exit(125);
  }

  if (ioctl(slave, TIOCSCTTY, 0) != 0) {
    fprintf(stderr, "TIOCSCTTY: %s\n", strerror(errno));
    _exit(125);
  }

  dup2(slave, STDIN_FILENO);
  dup2(slave, STDOUT_FILENO);
  dup2(slave, STDERR_FILENO);
  if (slave > STDERR_FILENO)
    close(slave);
}

static void raw_mode_enter(void)
{
  struct termios raw;

  if (!isatty(STDIN_FILENO))
    return;
  if (tcgetattr(STDIN_FILENO, &saved_termios) != 0)
    return;

  raw = saved_termios;
  cfmakeraw(&raw);
  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == 0)
    termios_saved = 1;
}

static void raw_mode_leave(void)
{
  if (!termios_saved)
    return;

  tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_termios);
  termios_saved = 0;
}

static int write_all(int fd, const char *buf, size_t len)
{
  while (len > 0) {
    ssize_t n = write(fd, buf, len);

    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }

    buf += n;
    len -= (size_t)n;
  }

  return 0;
}

static void relay(int master)
{
  struct pollfd fds[2];
  char buf[4096];
  int stdin_open = 1;

  signal(SIGWINCH, on_winch);

  for (;;) {
    ssize_t r;

    if (winch_pending) {
      winch_pending = 0;
      push_window_size(master);
    }

    fds[0].fd = stdin_open ? STDIN_FILENO : -1;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    fds[1].fd = master;
    fds[1].events = POLLIN;
    fds[1].revents = 0;

    if (poll(fds, 2, -1) < 0) {
      if (errno == EINTR)
        continue;
      break;
    }

    if (fds[1].revents) {
      r = read(master, buf, sizeof(buf));
      if (r < 0 && errno == EINTR)
        continue;
      /* The master reports EIO once the last slave closes. */
      if (r <= 0)
        break;
      if (write_all(STDOUT_FILENO, buf, (size_t)r) != 0)
        break;
    }

    if (fds[0].revents) {
      r = read(STDIN_FILENO, buf, sizeof(buf));
      if (r < 0 && errno == EINTR)
        continue;
      if (r <= 0)
        stdin_open = 0;
      else if (write_all(master, buf, (size_t)r) != 0)
        break;
    }
  }

  signal(SIGWINCH, SIG_DFL);
}

static void run_session(void)
{
  const char *base = strrchr(su_path, '/');
  char *const session_argv[] = { (char *)(base ? base + 1 : su_path),
                                 "-", NULL };
  int master, slave;
  pid_t pid, done;
  int status;

  open_pty(&master, &slave);

  pid = fork();
  if (pid < 0)
    die("fork");

  if (pid == 0) {
    signal(SIGINT, SIG_DFL);
    signal(SIGQUIT, SIG_DFL);

    close(master);
    attach_pty(slave);

    if (chdir(chroot_path) != 0 || chroot(chroot_path) != 0 ||
        chdir("/") != 0) {
      fprintf(stderr, "chroot %s: %s\n", chroot_path,
        strerror(errno));
      _exit(125);
    }

    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");

    dbg("chroot ok, exec %s", su_path);

    /* Go straight to the syscall. A preloaded library inherited from
       the launching shell (Termux's libtermux-exec) interposes
       execve() and rewrites the path to a prefix that does not exist
       inside the chroot. It is already mapped into this process, so
       clearing the environment above cannot disarm it. */
    syscall(SYS_execve, su_path, session_argv, environ);

    /* execve reports ENOENT both for a missing binary and for a
       binary whose ELF interpreter is missing. */
    if (errno == ENOENT && access(su_path, F_OK) == 0)
      fprintf(stderr, "exec %s: file exists, its ELF "
        "interpreter is missing\n", su_path);
    else
      fprintf(stderr, "exec %s: %s\n", su_path,
        strerror(errno));
    _exit(126);
  }

  /* Keep the cleanup path reachable when the session is interrupted. */
  signal(SIGINT, SIG_IGN);
  signal(SIGQUIT, SIG_IGN);

  /* The slave must not stay open on this side, or reading the master
     would never report end of file when the session exits. */
  close(slave);

  raw_mode_enter();
  relay(master);
  raw_mode_leave();
  close(master);

  do {
    done = waitpid(pid, &status, 0);
  } while (done < 0 && errno == EINTR);

  if (done < 0)
    dbg("waitpid: %s", strerror(errno));
  else if (WIFSIGNALED(status))
    dbg("session killed by signal %d", WTERMSIG(status));
  else
    dbg("session exited with %d", WEXITSTATUS(status));
}

static void usage(const char *prog)
{
  fprintf(stderr,
    "usage: %s [-i image] [-m mountpoint] [-s login] "
    "[-b host[:guest]]... [-d]\n"
    "  -i image        distro image file (default $HOME/distro.img)\n"
    "  -m mountpoint   absolute path to mount and chroot into "
    "(default %s)\n"
    "  -s login        login program run inside the chroot (default %s)\n"
    "  -b host[:guest] bind host path into the chroot at guest\n"
    "                  (guest defaults to host); repeatable\n"
    "  -d              enable debug output (same as DEBUG=1)\n",
    prog, DEFAULT_MOUNT, DEFAULT_SU);
}

int main(int argc, char **argv)
{
  const char *home = getenv("HOME");
  const char *image = NULL;
  const char *mount_at = DEFAULT_MOUNT;
  size_t len;
  int opt;

  debug_enabled = getenv("DEBUG") != NULL;

  while ((opt = getopt(argc, argv, "i:m:s:b:dh")) != -1) {
    switch (opt) {
    case 'i':
      image = optarg;
      break;
    case 'm':
      mount_at = optarg;
      break;
    case 's':
      su_path = optarg;
      break;
    case 'b': {
      char *sep = strchr(optarg, ':');

      if (bind_count >= MAX_BINDS) {
        fprintf(stderr, "too many -b binds (max %d)\n", MAX_BINDS);
        return 1;
      }
      if (sep)
        *sep = '\0';
      binds[bind_count].host = optarg;
      binds[bind_count].guest = sep ? sep + 1 : optarg;
      if (binds[bind_count].host[0] == '\0') {
        fprintf(stderr, "bind source is empty\n");
        return 1;
      }
      if (binds[bind_count].guest[0] != '/') {
        fprintf(stderr, "bind target must be absolute: %s\n",
          binds[bind_count].guest);
        return 1;
      }
      bind_count++;
      break;
    }
    case 'd':
      debug_enabled = 1;
      break;
    case 'h':
      usage(argv[0]);
      return 0;
    default:
      usage(argv[0]);
      return 2;
    }
  }

  if (image) {
    if ((size_t)snprintf(distro_path, sizeof(distro_path), "%s", image) >=
        sizeof(distro_path)) {
      fprintf(stderr, "distro image path is too long\n");
      return 1;
    }
  } else {
    if (!home || !*home) {
      fprintf(stderr, "HOME is not set and no image given (-i)\n");
      return 1;
    }
    if ((size_t)snprintf(distro_path, sizeof(distro_path), "%s/distro.img",
             home) >= sizeof(distro_path)) {
      fprintf(stderr, "distro image path is too long\n");
      return 1;
    }
  }

  /* The chroot must be absolute: the process-cleanup scan matches it
     against absolute /proc/<pid>/{exe,root,cwd} links. Trailing slashes
     are dropped so path joins and the sibling-boundary check stay exact. */
  if (mount_at[0] != '/') {
    fprintf(stderr, "mount point must be absolute: %s\n", mount_at);
    return 1;
  }
  len = strlen(mount_at);
  while (len > 1 && mount_at[len - 1] == '/')
    len--;
  if (len < 2) {
    fprintf(stderr, "invalid mount point: %s\n", mount_at);
    return 1;
  }
  if (len >= sizeof(chroot_path)) {
    fprintf(stderr, "mount point is too long\n");
    return 1;
  }
  memcpy(chroot_path, mount_at, len);
  chroot_path[len] = '\0';
  chroot_len = len;

  dbg("image=%s", distro_path);
  dbg("mount=%s", chroot_path);
  dbg("login=%s", su_path);

  do_mount();
  run_session();
  kill_chroot_processes();
  do_umount();

  return 0;
}
