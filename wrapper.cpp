// #define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <sys/socket.h>


extern "C" {

typedef void* (*mallocFuncType)(size_t) ;
typedef void (*freeFuncType)(void *);
typedef void* (*memcpyFuncType)(void*, void*, size_t);
typedef ssize_t (*recvFuncType)(int, void *, size_t, int);
typedef ssize_t (*recvfromFuncType)(int, void*, size_t, int, struct sockaddr*, socklen_t*);
typedef ssize_t (*recvmsgFuncType)(int, struct msghdr*, int);
typedef ssize_t (*readFuncType)(int, void*, size_t);
typedef ssize_t (*writeFuncType)(int, const void*, size_t);

// void *malloc(size_t size) {
//     mallocFuncType real_malloc = (mallocFuncType) dlsym(RTLD_NEXT, "malloc");
//     void *p = real_malloc(size);
//     fprintf(stderr, "in malloc(size: 0x%lx) => %p\n", size, p);
//     return p;
// }

// void free(void *p) {
//     freeFuncType real_free = (freeFuncType) dlsym(RTLD_NEXT, "free");
//     fprintf(stderr, "in free(p: %p)\n", p);
// }

void* memcpy(void *dst, void *src, size_t size) {
    memcpyFuncType real_memcpy = (memcpyFuncType) dlsym(RTLD_NEXT, "memcpy");
    // fprintf(stderr, "in memcpy(dst: %p, src: %p, size: 0x%lx)\n", dst, src, size);
    return real_memcpy(dst, src, size);
}


ssize_t recv(int socket, void *buffer, size_t length, int flags) {
    recvFuncType real_recv = (recvFuncType) dlsym(RTLD_NEXT, "recv");
    ssize_t ret = real_recv(socket, buffer, length, flags);
    fprintf(stderr, "in recv(socket: %d, buffer: %p, length: 0x%lx, flags: %d) => %zd\n", socket, buffer, length, flags, ret);
    return ret;
}


ssize_t recvfrom(int socket, void *buffer, size_t length, int flags, struct sockaddr *address, socklen_t *address_len) {
    recvfromFuncType real_recvfrom = (recvfromFuncType) dlsym(RTLD_NEXT, "recvfrom");
    ssize_t ret = real_recvfrom(socket, buffer, length, flags, address, address_len);
    fprintf(stderr, "in recvfrom(socket: %d, buffer: %p, length: 0x%lx, flags: %d) => %zd\n", socket, buffer, length, flags, ret);
    return ret;
}


ssize_t recvmsg(int socket, struct msghdr *mhdr, int flags) {
    recvmsgFuncType real_recvmsg = (recvmsgFuncType) dlsym(RTLD_NEXT, "recvmsg");
    ssize_t ret = real_recvmsg(socket, mhdr, flags);
    fprintf(stderr, "in recvmsg(socket: %d, mhdr: %p, flags: %d) => %zd\n", socket, mhdr, flags, ret);
    return ret;
}


ssize_t read(int fd, void *buf, size_t count) {
    readFuncType real_read = (readFuncType) dlsym(RTLD_NEXT, "read");
    ssize_t ret = real_read(fd, buf, count);
    fprintf(stderr, "in read(fd: %d, buf: %p, size: 0x%lx) => %zd\n", fd, buf, count, ret);
    return ret;
}


// ssize_t write(int fd, const void *buf, size_t count) {
//     writeFuncType real_write = (writeFuncType) dlsym(RTLD_NEXT, "write");
//     ssize_t ret = real_write(fd, buf, count);
//     fprintf(stderr, "in write(fd: %d, buf: %p, size: 0x%lx) => %zd\n", fd, buf, count, ret);
//     return ret;
// }

}