// SPDX-License-Identifier: Apache-2.0
// Offline merged-root export inside a disposable Guest. The destination is an
// empty, independently formatted ext4; source OverlayFS owns whiteout, redirect
// and index interpretation. No userspace reimplementation of those semantics.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#define BUCKETS 16384
struct hardlink { dev_t dev; ino_t ino; char *path; struct hardlink *next; };
static struct hardlink *links[BUCKETS];
static int dest_root;
static dev_t source_dev;
static uint64_t copied_bytes, copied_files;

static void die(const char *what) { perror(what); exit(1); }
static void *alloc(size_t size) { void *p = malloc(size); if (!p) die("malloc"); return p; }
static char *join(const char *parent, const char *name) {
    char *p; if (asprintf(&p, "%s%s%s", parent, *parent ? "/" : "", name) < 0) die("asprintf"); return p;
}
static char *fdpath(int dir, const char *name) {
    char *p; if (asprintf(&p, "/proc/self/fd/%d/%s", dir, name) < 0) die("asprintf"); return p;
}

// Apply semantic inode flags only after every byte, attribute and hardlink
// has been copied. Applying immutable/append-only earlier would block export.
#define SEMANTIC_FLAGS (FS_SYNC_FL | FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL | FS_NOATIME_FL | FS_DIRSYNC_FL | FS_TOPDIR_FL)
struct deferred_flag { char *path; long flags; struct deferred_flag *next; };
static struct deferred_flag *flag_head, **flag_tail = &flag_head;
static long read_flags(int fd) {
    long flags = 0;
    if (ioctl(fd, FS_IOC_GETFLAGS, &flags)) {
        if (errno == ENOTTY || errno == EOPNOTSUPP) return 0;
        die("read inode flags");
    }
    return flags & SEMANTIC_FLAGS;
}
static void write_flags(int fd, long wanted) {
    long flags = 0;
    if (ioctl(fd, FS_IOC_GETFLAGS, &flags)) die("read destination inode flags");
    flags = (flags & ~SEMANTIC_FLAGS) | wanted;
    if (ioctl(fd, FS_IOC_SETFLAGS, &flags)) die("restore inode flags");
}
static void remember_flags(int srcdir, const char *name, const struct stat *st, const char *rel) {
    if (!S_ISREG(st->st_mode) && !S_ISDIR(st->st_mode)) return;
    int fd = openat(srcdir,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if (fd < 0) die("open inode flags source");
    long flags = read_flags(fd); if (close(fd)) die("close inode flags source");
    if (!flags) return;
    struct deferred_flag *f = alloc(sizeof(*f));
    *f = (struct deferred_flag){.path=strdup(*rel ? rel : "."),.flags=flags};
    if (!f->path) die("strdup flags");
    *flag_tail = f; flag_tail = &f->next;
}
static void apply_flags(void) {
    for (struct deferred_flag *f=flag_head; f; f=f->next) {
        int fd=openat(dest_root,f->path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
        if (fd<0) die("open inode flags target");
        write_flags(fd,f->flags); if (close(fd)) die("close inode flags target");
    }
}

static void attributes(int srcdir, int dstdir, const char *name, const struct stat *st) {
    // Ownership and mode precede xattrs: chown/chmod can clear capabilities or
    // alter ACL masks. Symlink attributes must never follow their target.
    if (fchownat(dstdir, name, st->st_uid, st->st_gid, AT_SYMLINK_NOFOLLOW)) die("copy ownership");
    if (!S_ISLNK(st->st_mode) && fchmodat(dstdir, name, st->st_mode & 07777, 0)) die("copy mode");
    char *src = fdpath(srcdir, name), *dst = fdpath(dstdir, name);
    ssize_t len = llistxattr(src, NULL, 0);
    if (len < 0) die("list xattrs");
    char *names = alloc((size_t)len + 1);
    // OverlayFS may return a conservative size including private attributes
    // and a shorter filtered list on the second call. Use the returned length.
    ssize_t listed = llistxattr(src, names, (size_t)len);
    if (listed < 0 || listed > len) die("read xattr names");
    len = listed;
    for (char *key = names; key < names + len; key += strlen(key) + 1) {
        // Overlay-private attributes must not become attributes of the new
        // plain ext4 root. ACLs, capabilities and other namespaces are kept.
        if (!strncmp(key, "trusted.overlay.", 16) || !strncmp(key, "user.overlay.", 13)) continue;
        ssize_t size = lgetxattr(src, key, NULL, 0);
        if (size < 0) die("measure xattr");
        void *value = alloc((size_t)size + 1);
        ssize_t got = lgetxattr(src, key, value, (size_t)size);
        if (got < 0 || got > size) die("read xattr");
        if (lsetxattr(dst, key, value, (size_t)got, 0)) die("copy xattr");
        free(value);
    }
    struct timespec times[2] = {st->st_atim, st->st_mtim};
    if (utimensat(dstdir, name, times, AT_SYMLINK_NOFOLLOW)) die("copy timestamps");
    free(names); free(src); free(dst);
}

static void range_copy(int src, int dst, off_t start, off_t end) {
    unsigned char buffer[128 * 1024];
    while (start < end) {
        size_t want = end - start < (off_t)sizeof(buffer) ? (size_t)(end - start) : sizeof(buffer);
        ssize_t got = pread(src, buffer, want, start);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { if (!got) errno = EIO; die("read file data"); }
        // Also preserves zero holes when the backing filesystem cannot report
        // SEEK_DATA. Allocated zero extents may become holes; bytes are equal.
        size_t i = 0; while (i < (size_t)got && buffer[i] == 0) i++;
        if (i != (size_t)got) {
            ssize_t done = 0;
            while (done < got) {
                ssize_t n = pwrite(dst, buffer + done, (size_t)(got - done), start + done);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) die("write file data");
                done += n;
            }
        }
        copied_bytes += (uint64_t)got;
        start += got;
    }
}

static void regular(int srcdir, int dstdir, const char *name, const struct stat *st) {
    int src = openat(srcdir, name, O_RDONLY | O_NOFOLLOW | O_NOATIME | O_CLOEXEC);
    if (src < 0) die("open source file");
    struct stat now;
    if (fstat(src, &now) || now.st_dev != st->st_dev || now.st_ino != st->st_ino || now.st_size != st->st_size || !S_ISREG(now.st_mode)) {
        errno = ESTALE; die("source file changed");
    }
    int dst = openat(dstdir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (dst < 0) die("create destination file");
    off_t cursor = 0;
    while (cursor < st->st_size) {
        off_t data = lseek(src, cursor, SEEK_DATA);
        if (data < 0) {
            if (errno == ENXIO) break;
            if (errno != EINVAL && errno != EOPNOTSUPP) die("seek data");
            range_copy(src, dst, cursor, st->st_size); break;
        }
        off_t hole = lseek(src, data, SEEK_HOLE);
        if (hole <= data) die("seek hole");
        if (hole > st->st_size) hole = st->st_size;
        range_copy(src, dst, data, hole); cursor = hole;
    }
    if (ftruncate(dst, st->st_size) || close(dst) || close(src)) die("finish file");
    attributes(srcdir, dstdir, name, st);

}

static size_t bucket_for(const struct stat *st) { return ((uint64_t)st->st_ino ^ (uint64_t)st->st_dev) % BUCKETS; }
static int existing_link(int dst, const char *name, const struct stat *st) {
    if (S_ISDIR(st->st_mode) || S_ISSOCK(st->st_mode) || st->st_nlink < 2) return 0;
    for (struct hardlink *p = links[bucket_for(st)]; p; p = p->next) {
        if (p->dev == st->st_dev && p->ino == st->st_ino) {
            if (linkat(dest_root,p->path,dst,name,0)) die("copy hardlink");
            return 1;
        }
    }
    return 0;
}
static void remember_link(const struct stat *st, const char *rel) {
    if (S_ISDIR(st->st_mode) || S_ISSOCK(st->st_mode) || st->st_nlink < 2) return;
    size_t bucket = bucket_for(st);
    struct hardlink *p = alloc(sizeof(*p));
    *p = (struct hardlink){.dev=st->st_dev,.ino=st->st_ino,.path=strdup(rel),.next=links[bucket]};
    if (!p->path) die("strdup");
    links[bucket] = p;
}

static int transient_root(const char *name) {
    return !strcmp(name, "dev") || !strcmp(name, "proc") || !strcmp(name, "sys") || !strcmp(name, "run");
}

static void tree(int src, int dst, const char *relative) {
    DIR *dir = fdopendir(dup(src)); if (!dir) die("open source directory");
    struct dirent *entry;
    for (;;) {
        errno = 0; entry = readdir(dir);
        if (!entry) { if (errno) die("read directory"); break; }
        const char *name = entry->d_name;
        if (!strcmp(name,".") || !strcmp(name,"..")) continue;
        struct stat st; if (fstatat(src, name, &st, AT_SYMLINK_NOFOLLOW)) die("stat source entry");
        if (!*relative && (!strcmp(name,".e2b-rootfs") || (!strcmp(name,".e2b") && S_ISDIR(st.st_mode)))) continue;
        char *rel = join(relative,name);
        if (existing_link(dst,name,&st)) { copied_files++; free(rel); continue; }
        if (S_ISDIR(st.st_mode)) {
            if (mkdirat(dst,name,0700)) die("create directory");
            int from = openat(src,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NOATIME|O_CLOEXEC);
            int to = openat(dst,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            if (from < 0 || to < 0) die("open directory");
            // Mountpoints and transient root trees retain their directory
            // metadata, but never import proc/sys/dev/run contents.
            if (st.st_dev == source_dev && !(!*relative && transient_root(name))) tree(from,to,rel);
            if (close(from) || close(to)) die("close directory");
            attributes(src,dst,name,&st);
        } else if (S_ISREG(st.st_mode)) {
            regular(src,dst,name,&st);
        } else if (S_ISLNK(st.st_mode)) {
            size_t cap = (size_t)st.st_size + 1;
            char *target = alloc(cap + 1);
            ssize_t n = readlinkat(src,name,target,cap);
            if (n < 0 || (size_t)n >= cap) die("read symlink");
            target[n] = 0;
            if (symlinkat(target,dst,name)) die("copy symlink");
            free(target); attributes(src,dst,name,&st);
        } else if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode) || S_ISFIFO(st.st_mode)) {
            if (mknodat(dst,name,st.st_mode,st.st_rdev)) die("copy special file");
            attributes(src,dst,name,&st);
        } else if (S_ISSOCK(st.st_mode)) {
            fprintf(stderr,"rootfs-copy: omitted inactive socket %s\n",rel);
        } else { errno = EINVAL; die("unsupported file type"); }
        remember_flags(src,name,&st,rel); remember_link(&st,rel); copied_files++; free(rel);
    }
    if (closedir(dir)) die("close source directory");
}

int main(int argc, char **argv) {
    int metadata_only = argc == 4 && !strcmp(argv[1], "--root-metadata");
    int flags_only = argc == 4 && !strcmp(argv[1], "--root-flags");
    if (metadata_only || flags_only) { argc--; argv++; }
    if (argc != 3) { fprintf(stderr,"usage: rootfs-copy SOURCE EMPTY_DESTINATION\n"); return 2; }
    int src = open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NOATIME|O_CLOEXEC);
    dest_root = open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (src < 0 || dest_root < 0) die("open roots");
    struct stat st, target;
    if (fstat(src,&st) || fstat(dest_root,&target)) die("stat roots");
    if (st.st_dev == target.st_dev && st.st_ino == target.st_ino) { errno=EINVAL; die("roots alias"); }
    if (flags_only) {
        write_flags(dest_root,read_flags(src));
        if (syncfs(dest_root)) die("sync root flags");
        return 0;
    }
    if (metadata_only) {
        attributes(src,dest_root,".",&st);
        if (syncfs(dest_root)) die("sync root metadata");
        return 0;
    }
    // The caller formats the target first and removes its empty lost+found.
    DIR *dir = fdopendir(dup(dest_root)); if (!dir) die("open destination");
    struct dirent *e;
    while ((e=readdir(dir))) if (strcmp(e->d_name,".") && strcmp(e->d_name,"..")) { errno=ENOTEMPTY; die("destination must be empty"); }
    closedir(dir); source_dev=st.st_dev;
    tree(src,dest_root,"");
    attributes(src,dest_root,".",&st);
    remember_flags(src,".",&st,""); apply_flags();
    if (syncfs(dest_root)) die("sync export");
    printf("E2B_ROOTFS_COPY_OK files=%" PRIu64 " data_bytes=%" PRIu64 "\n",copied_files,copied_bytes);
    return 0;
}
