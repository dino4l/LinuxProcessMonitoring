
# LinuxProcessMonitoring
A loadable module of the Linux OS kernel for monitoring the creation of child processes and sending them to the server


## Instalation:

```
> make
```

```
> sudo insmod linux_kernel_monitor.ko
```

```
> sudo insmod linux_kernel_monitor.ko
```

Intercepting the sys_clone() call

![image](https://user-images.githubusercontent.com/81106878/132882926-0504a7ee-71d3-49f9-becb-7a8d607b82b3.png)

Staring the server 

```
> telnet 'ip' 'port'
```

![image](https://user-images.githubusercontent.com/81106878/132883222-ee019ad2-20e8-4c6b-a1d9-685b42b23160.png)

To unload this module:

```
> sudo rmmod linux_kernel_monitor.ko
```


