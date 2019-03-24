// #define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <sys/socket.h>


extern "C" {

typedef void* (*mallocFuncType)(size_t) ;
typedef void* (*memcpyFuncType)(void*, void*, size_t);
typedef ssize_t (*recvFuncType)(int, void *, size_t, int);
typedef ssize_t (*recvfromFuncType)(int, void*, size_t, int, struct sockaddr*, socklen_t*);
typedef ssize_t (*recvmsgFuncType)(int, struct msghdr*, int);


void *malloc(size_t size) {
    mallocFuncType real_malloc = (mallocFuncType) dlsym(RTLD_NEXT, "malloc");
    void *p = real_malloc(size);
    fprintf(stderr, "malloc(size: 0x%lx) => addr: %p\n", size, p);
    return p;
}


void* memcpy(void *dst, void *src, size_t size) {
    memcpyFuncType real_memcpy = (memcpyFuncType) dlsym(RTLD_NEXT, "memcpy");
    fprintf(stderr, "memcpy(dst: %p, src: %p, size: 0x%lx)\n", dst, src, size);
    return real_memcpy(dst, src, size);
}


ssize_t recv(int socket, void *buffer, size_t length, int flags) {
    recvFuncType real_recv = (recvFuncType) dlsym(RTLD_NEXT, "recv");
    ssize_t s = real_recv(socket, buffer, length, flags);
    fprintf(stderr, "recv(sock:%d, buffer: %p, length: 0x%lx, flags: %d) => len: 0x%lx\n", socket, buffer, length, flags, s);
    return s;
}


ssize_t recvfrom(int socket, void *buffer, size_t length, int flags, struct sockaddr *address, socklen_t *address_len) {
    recvfromFuncType real_recvfrom = (recvfromFuncType) dlsym(RTLD_NEXT, "recvfrom");
    ssize_t s = real_recvfrom(socket, buffer, length, flags, address, address_len);
    fprintf(stderr, "recvfrom(sock:%d, buffer: %p, length: 0x%lx, flags: %d) => len: 0x%lx\n", socket, buffer, length, flags, s);
    return s;
}


ssize_t recvmsg(int socket, struct msghdr *mhdr, int flags) {
    recvmsgFuncType real_recvmsg = (recvmsgFuncType) dlsym(RTLD_NEXT, "recvmsg");
    ssize_t s = real_recvmsg(socket, mhdr, flags);
    fprintf(stderr, "recvmsg(sock:%d, mhdr: %p, flags: %d) => len: 0x%lx\n", socket, mhdr, flags, s);
    return s;
}


}