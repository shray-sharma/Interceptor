# Interceptor
An assignment for CSC209. Note to UofT students, please **do not plagarize**. MarkUs ***will*** catch you.  
---
A kernel module used to intercept/hijack system calls and monitor processes.

We implemented a new system call named `my_syscall`, which will allow you to send commands from userspace, to intercept another pre-existing system call (like read, write, open, etc.). After a system call is intercepted, the intercepted system call would log a message first before continuing performing what it was supposed to do.

The new system call my_syscall, defined as follows: 
```C
int my_syscall(int cmd, int syscall, int pid);
```
will serve as an interceptor and will receive the following commands from userspace:
 * **REQUEST_SYSCALL_INTERCEPT:** intercept the system call syscall
 * **REQUEST_SYSCALL_RELEASE:** de-intercept the system call syscall
 * **REQUEST_START_MONITORING:** start monitoring process pid for system call syscall, i.e., add pid to the syscall's list of monitored PIDs. If pid is 0 then all processes are monitored for syscall, but only root has the permission to issue this command.
 * **REQUEST_STOP_MONITORING:** stop monitoring process pid for system call syscall, i.e., remove pid from the syscall's list of monitored PIDs.
