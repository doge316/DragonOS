#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
    long ret = syscall(2333); // 调用 2333 号系统调用
    printf("syscall 2333 returned: %ld\n", ret);
    return 0;
}
