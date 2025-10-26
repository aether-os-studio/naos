#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

void *thread_func(void *arg) {
    printf("Child thread running, TID=%d\n", gettid());
    sleep(1);
    return NULL;
}

int main() {
    pthread_t thread;
    
    printf("Parent TID: %d\n", gettid());
    
    // pthread_create 内部会使用 CLONE_SETTLS
    int ret = pthread_create(&thread, NULL, thread_func, NULL);
    
    printf("After pthread_create, ret=%d\n", ret);
    printf("Parent still running\n");  // ⚠️ 这里会触发 stack_chk_fail 吗？
    
    pthread_join(thread, NULL);
    printf("Thread joined\n");
    
    return 0;
}
