#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/linkage.h>
#include <linux/uaccess.h>

#include <linux/errno.h>
#include <linux/types.h>

#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <linux/unistd.h>
#include <linux/wait.h>

#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/request_sock.h>

#define DEFAULT_PORT 8080
#define MAX_CONNECTIONSS 16
#define MSG_LEN 64
#define MODULE_NAME "linux_kernel_monitor"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tsoraev Rolan");

int tcp_list_stop = 0;
int tcp_accept_stop = 0;

// структура, описывающая и хранящая данные о тек. соединении для каждого клиента
struct tcp_data_handler {
    struct sockaddr_in *address;
    struct socket *socket_accept;
    int thread_id;
};
// структура, описывающая и хранящая данные о тек. соединениях для всех клиентов
struct tcp_connect_handler {
    struct tcp_data_handler *data[MAX_CONNECTIONSS];
    struct task_struct *thread[MAX_CONNECTIONSS];
    int tcp_connect_handler_stopped[MAX_CONNECTIONSS];
};
// Выделение памяти для структуры tcp_connect_handler
struct tcp_connect_handler *tcp_connect_handler;
// структура, описывающая весь сервис
struct tcp_server_structure {
    int is_running;
    struct socket *socket_listen;
    struct task_struct *thread;
    struct task_struct *thread_accept;
};
// Выделение памяти для структуры tcp_server_structure
struct tcp_server_structure *tcp_server;
// Функция преобразования адресов из точечно-десятичной в 32 разрядное двоичное значение в сетевом порядке байтов
char *inet_ntoa(struct in_addr *in)
{
    char *str_ip = NULL;
    u_int32_t int_ip = 0;

    if (!(str_ip = kmalloc(16 * sizeof(char), GFP_KERNEL))) {
        return NULL;
    } else {
        memset(str_ip, 0, 16);
    }

    int_ip = in->s_addr;
    sprintf(str_ip, "%d.%d.%d.%d", (int_ip) & 0xFF, (int_ip >> 8) & 0xFF, (int_ip >> 16) & 0xFF, (int_ip >> 16) & 0xFF);

    return str_ip;
}
// отправка с сервера
int tcp_sending_from_server(struct socket *sock, int id, const char *buf, const size_t length, unsigned long flags)
{
    struct msghdr msg;
    struct kvec vec;
    int len, written = 0, left = length;
    mm_segment_t oldmm;

    msg.msg_name    = 0;
    msg.msg_namelen = 0;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = flags;
    msg.msg_flags   = 0;

    oldmm = get_fs();
    set_fs(KERNEL_DS);

    while (1) {
        vec.iov_len = left;
        vec.iov_base = (char *)buf + written;
        len = kernel_sendmsg(sock, &msg, &vec, left, left);

        if ((len == -ERESTARTSYS) || (!(flags & MSG_DONTWAIT) && (len == -EAGAIN))) {
            continue;
        }

        if (len > 0) {
            written += len;
            left -= len;

            if (!left) {
                break;
            }
        }
    }

    set_fs(oldmm);
    return written ? written : len;
}
// получение данных от сервера
int tcp_receive_from_server(struct socket *sock, int id, struct sockaddr_in *address, unsigned char *buf, int size, unsigned long flags)
{
    struct msghdr msg;
    struct kvec vec;
    int len;
    char *tmp = NULL;

    if (sock == NULL) {
        pr_info(" *** tcp server receive socket is NULL | tcp_receive_from_server *** \n");
        return -1;
    }

    msg.msg_name = 0;
    msg.msg_namelen = 0;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = flags;

    vec.iov_len = size;
    vec.iov_base = buf;

    while (1) {
        if (!skb_queue_empty(&sock->sk->sk_receive_queue)) {
            pr_info("recv queue empty ? %s \n", skb_queue_empty(&sock->sk->sk_receive_queue) ? "yes" : "no");
        }

        len = kernel_recvmsg(sock, &msg, &vec, size, size, flags);

        if (len != -EAGAIN && len != -ERESTARTSYS) {
            break;
        }
    }

    tmp = inet_ntoa(&(address->sin_addr));
    pr_info("client-> %s:%d, says: %s\n", tmp, ntohs(address->sin_port), buf);
    kfree(tmp);

    return len;
}
// Функция обработчик подключения
int connection_handler(void *data)
{
    struct tcp_data_handler *conn_data = (struct tcp_data_handler *)data;
    struct sockaddr_in *address = conn_data->address;
    struct socket *socket_accept = conn_data->socket_accept;

    int id = conn_data->thread_id;
    int ret;
    unsigned char in_buf[MSG_LEN];

    DECLARE_WAITQUEUE(recv_wait, current);
    allow_signal(SIGKILL | SIGSTOP);

    while (1) {
        add_wait_queue(&socket_accept->sk->sk_wq->wait, &recv_wait);

        while (skb_queue_empty(&socket_accept->sk->sk_receive_queue)) {
            __set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(HZ);

            if (kthread_should_stop()) {
                pr_info(" *** tcp server handle connection thread stopped | connection_handler *** \n");
                tcp_connect_handler->tcp_connect_handler_stopped[id] = 1;

                __set_current_state(TASK_RUNNING);
                remove_wait_queue(&socket_accept->sk->sk_wq->wait, &recv_wait);
                kfree(tcp_connect_handler->data[id]->address);
                kfree(tcp_connect_handler->data[id]);
                sock_release(tcp_connect_handler->data[id]->socket_accept);

                return 0;
            }

            if (signal_pending(current)) {
                __set_current_state(TASK_RUNNING);
                remove_wait_queue(&socket_accept->sk->sk_wq->wait, &recv_wait);
                goto release;
            }
        }

        __set_current_state(TASK_RUNNING);
        remove_wait_queue(&socket_accept->sk->sk_wq->wait, &recv_wait);

        pr_info("receiving message\n");
        memset(in_buf, 0, MSG_LEN);
        ret = tcp_receive_from_server(socket_accept, id, address, in_buf, MSG_LEN, MSG_DONTWAIT);

        if (ret > 0) {
            if (memcmp(in_buf, "done", 4) == 0) {
                    memset(in_buf, 0, MSG_LEN);
                    strcat(in_buf, "Connection closed... See you again");
                    tcp_sending_from_server(socket_accept, id, in_buf, strlen(in_buf), MSG_DONTWAIT);
                    break;
            }
        }
    }

release:
    tcp_connect_handler->tcp_connect_handler_stopped[id] = 1;
    kfree(tcp_connect_handler->data[id]->address);
    kfree(tcp_connect_handler->data[id]);
    tcp_connect_handler->data[id] = NULL;
    sock_release(tcp_connect_handler->data[id]->socket_accept);
    tcp_connect_handler->thread[id] = NULL;

    do_exit(0);
}
// Создается новый поток для принятия соединений, ему на вход перед. эта фунция
int tcp_accept_from_server(void)
{
    struct socket *socket;
    struct socket *socket_accept = NULL;
    struct inet_connection_sock *isock;
    int accept_err = 0, id = 0;

    DECLARE_WAITQUEUE(accept_wait, current);
    allow_signal(SIGKILL | SIGSTOP);

    socket = tcp_server->socket_listen;
    pr_info(" *** creating the accept socket | tcp_accept_from_server *** \n");

    while (1) {
        struct tcp_data_handler *data = NULL;
        struct sockaddr_in *client = NULL;
        char *tmp;
        int addr_len;
        accept_err = sock_create(socket->sk->sk_family, socket->type, socket->sk->sk_protocol, &socket_accept);
        pr_info("socket_accept: %p\n", socket_accept);

        if (accept_err < 0 || !socket_accept) {
            pr_info(" *** accept_error: %d while creating tcp server accept socket | tcp_accept_from_server *** \n", accept_err);
            goto err;
        }

        socket_accept->type = socket->type;
        socket_accept->ops  = socket->ops;
        isock = inet_csk(socket->sk);
        add_wait_queue(&socket->sk->sk_wq->wait, &accept_wait);

        while (reqsk_queue_empty(&isock->icsk_accept_queue)) {
            __set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(HZ);

            if (kthread_should_stop()) {
                pr_info(" *** tcp server acceptor thread stopped | tcp_accept_from_server *** \n");
                tcp_accept_stop = 1;
                __set_current_state(TASK_RUNNING);
                remove_wait_queue(&socket->sk->sk_wq->wait, &accept_wait);
                sock_release(socket_accept);
                return 0;
            }

            if (signal_pending(current)) {
                __set_current_state(TASK_RUNNING);
                remove_wait_queue(&socket->sk->sk_wq->wait, &accept_wait);
                goto release;
            }

        }

        __set_current_state(TASK_RUNNING);
        remove_wait_queue(&socket->sk->sk_wq->wait, &accept_wait);
        pr_info("accept connection\n");
        accept_err = socket->ops->accept(socket, socket_accept, O_NONBLOCK, false);

        if (accept_err < 0) {
            pr_info(" *** accept_error: %d while accepting tcp server | tcp_accept_from_server *** \n", accept_err);
            goto release;
        }

        client = kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);
        memset(client, 0, sizeof(struct sockaddr_in));
        addr_len = sizeof(struct sockaddr_in);
        accept_err = socket_accept->ops->getname(socket_accept, (struct sockaddr *)client, addr_len);

        if (accept_err < 0) {
            pr_info(" *** accept_error: %d in getname tcp server | tcp_accept_from_server *** \n", accept_err);
            goto release;
        }

        tmp = inet_ntoa(&(client->sin_addr));
        pr_info("connection from: %s %d \n", tmp, ntohs(client->sin_port));
        kfree(tmp);
        pr_info("handle connection\n");

        for (id = 0; id < MAX_CONNECTIONSS; id++) {
            if (tcp_connect_handler->thread[id] == NULL)
                break;
        }
        
        pr_info("gave free id: %d\n", id);

        if (id == MAX_CONNECTIONSS) {
            goto release;
        }

        data = kmalloc(sizeof(struct tcp_data_handler), GFP_KERNEL);
        memset(data, 0, sizeof(struct tcp_data_handler));

        data->address = client;
        data->socket_accept = socket_accept;
        data->thread_id = id;

        tcp_connect_handler->tcp_connect_handler_stopped[id] = 0;
        tcp_connect_handler->data[id] = data;
        tcp_connect_handler->thread[id] = kthread_run((void *)connection_handler, (void *)data, MODULE_NAME);

        if (kthread_should_stop()) {
            pr_info(" *** tcp server acceptor thread stopped | tcp_accept_from_server *** \n");
            tcp_accept_stop = 1;
            return 0;
        }

        if (signal_pending(current)) {
            break;
        }
    }

release:
    sock_release(socket_accept);

err:
    tcp_accept_stop = 1;
    do_exit(0);
}
// Функция делает стандартную последовательность действий для любого сервера: заполняет структуру sockaddr_in
// Далее вызывает фукнции bind и listen
int tcp_server_listener(void)
{
    int server_err;
    struct socket *conn_socket;
    struct sockaddr_in server;

    DECLARE_WAIT_QUEUE_HEAD(wq);
    allow_signal(SIGKILL | SIGTERM);

    if ((server_err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &tcp_server->socket_listen)) < 0) {
        pr_info(" *** Error: %d while creating tcp server listen socket | tcp_server_listener *** \n", server_err);
        goto err;
    }

    conn_socket = tcp_server->socket_listen;
    tcp_server->socket_listen->sk->sk_reuse = 1;

    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_family = AF_INET;
    server.sin_port = htons(DEFAULT_PORT);

    if ((server_err = conn_socket->ops->bind(conn_socket, (struct sockaddr*)&server, sizeof(server))) < 0) {
        pr_info(" *** Error: %d while binding tcp server listen socket | tcp_server_listener *** \n", server_err);
        goto release;
    }

    if ((server_err = conn_socket->ops->listen(conn_socket, MAX_CONNECTIONSS)) < 0) {
        pr_info(" *** Error: %d while listening in tcp server listen socket | tcp_server_listener *** \n", server_err);
        goto release;
    }
	// Создается новый поток для принятия соединений, ему на вход подается tcp_accept_from_server
	// А ранее созданный поток переходит в режим ожидания событий
    tcp_server->thread_accept = kthread_run((void*)tcp_accept_from_server, NULL, MODULE_NAME);

    while (1) {
        wait_event_timeout(wq, 0, 3 * HZ);

        if (kthread_should_stop()) {
            pr_info(" *** tcp server listening thread stopped | tcp_server_listener *** \n");
            return 0;
        }

        if (signal_pending(current)) {
            break;
        }
    }

release:
    sock_release(conn_socket);

err:
    tcp_list_stop = 1;
    do_exit(0);
}
// Установление флага is_running = 1, старт сервера
// Создается поток, слушающий все приходящие соединения, которому на вход подается
// функция tcp_server_listener
int tcp_start_server(void)
{
    tcp_server->is_running = 1;
    tcp_server->thread = kthread_run((void *)tcp_server_listener, NULL, MODULE_NAME);
    return 0;
}
// Инициализация сетевого сервера
static int network_server_init(void)
{
    pr_info(" *** network_server initiated | network_server_init ***\n");
    tcp_server = kmalloc(sizeof(struct tcp_server_structure), GFP_KERNEL);
    memset(tcp_server, 0, sizeof(struct tcp_server_structure));

    tcp_connect_handler = kmalloc(sizeof(struct tcp_connect_handler), GFP_KERNEL);
    memset(tcp_connect_handler, 0, sizeof(struct tcp_connect_handler));

    tcp_start_server();
    return 0;
}

// Фукнция выключения сервера
static void server_exit(void)
{
    int ret;
    int id;

    if (tcp_server->thread == NULL)
        pr_info(" *** No kernel thread to kill | server_exit *** \n");
    else {
        for (id = 0; id < MAX_CONNECTIONSS; id++) {
            if (tcp_connect_handler->thread[id] != NULL) {
                if (!tcp_connect_handler->tcp_connect_handler_stopped[id]) {
                    if (!(ret = kthread_stop(tcp_connect_handler->thread[id]))) {
                        pr_info(" tcp server connection handler thread: %d stopped | server_exit *** \n", id);
                    }
                }
            }
        }

        if (!tcp_accept_stop) {
            if (!(ret = kthread_stop(tcp_server->thread_accept)))
                pr_info(" *** tcp server acceptor thread stopped | server_exit *** \n");
        }

        if (!tcp_list_stop) {
            if (!(ret = kthread_stop(tcp_server->thread)))
                pr_info(" *** tcp server listening thread stopped | server_exit *** \n");
        }

        if (tcp_server->socket_listen != NULL && !tcp_list_stop) {
            sock_release(tcp_server->socket_listen);
            tcp_server->socket_listen = NULL;
        }

        kfree(tcp_connect_handler);
        kfree(tcp_server);
        tcp_server = NULL;
    }

    pr_info(" *** mtp | network server module unloaded | server_exit *** \n");
}

#define HOOK(_name, _function, _original)	\
	{					\
	       .name = (_name),		\
		.mimic_function = (_function),	\
		.original_function = (_original),	\
	}

/**
* struct ftrace_intercept - описывает перехватываемую функцию
*
* @name:       имя перехватываемой функции
* @function:   адрес функции-обёртки, которая будет вызываться вместо
*              перехваченной функции
* @original:   указатель на место, куда следует записать адрес
*              перехватываемой функции, заполняется при установке
* @address:    адрес перехватываемой функции, выясняется при установке
* @ops:        служебная информация ftrace, инициализируется нулями,
*              при установке перехвата будет доинициализирована
*/
// Всю информацию, необходимую ftrace для перехвата функции, можно описать структурой
struct ftrace_intercept {
	const char *name;
	void *mimic_function;
	void *original_function;

	unsigned long address;
	struct ftrace_ops ops;
};

#define USE_FENTRY_OFFSET 0
#define pr_fmt(fmt) "ftrace_intercept: " fmt

// Поиск адреса функции, которую будем перехватывать
// Процесс получения адреса подключенной функции, используется kallsyms - список всех символов ядра
static int fh_resolve_intercept_addr(struct ftrace_intercept *hook)
{
	if (!(hook->address = kallsyms_lookup_name(hook->name))) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original_function) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original_function) = hook->address;
#endif

	return 0;
}
// Обратный вызов для ftrace, который вызывается при трассировании функции
// Изменяя регистр %rip — указатель на следующую исполняемую инструкцию,— мы изменяем инструкции, которые исполняет процессор
// т.е. можем заставить его выполнить безусловный переход из текущей функции в нашу. Таким образом мы перехватываем управление
// на себя. Notrace помогает предотвратить зависание системы в бесконечном цикле
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct pt_regs *regs)
{
	//получаем адрес struct ftrace_intrecept для нашей функции с помощью макроса container_of()
	// по адресу внедренной в нее struct ftrace_ops
	struct ftrace_intercept *hook = container_of(ops, struct ftrace_intercept, ops);

	// заменяем значение регистра %rip в структуре
	// struct pt_rewgs на адрес нашего обработчика
#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long) hook->mimic_function;
#else
	// при помощи parent_ip можно отличить первый вызов перехваченной функции от повторной
	if (!within_module(parent_ip, THIS_MODULE)) {
		regs->ip = (unsigned long) hook->mimic_function;
        }
#endif
}
// Регистрация и активация перехвата
// Важные флаги для инициализации структуры ftrace_ops
int fh_install_intercept(struct ftrace_intercept *hook)
{
	int err;

	if ((err = fh_resolve_intercept_addr(hook))) {
		return err;
        }
	
	/** Для модификации регистра %rip необходим флаг IPMODIFY и SAVE_REGS. 
	* Флаги предписывают ftrace сохранить и восстановить регистры процессора, содержимое которых мы
	* можем изменить в коллбеке. Защита ftrace от рекурсии бесполезна, если изменять %rip, поэтому
	* выключаем ее с помощью RECURSION_SAFE.
	* Проверка для защиты от рекурсии будет выполнятся на входе в трассируемую функцию
	*/
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION_SAFE
	                | FTRACE_OPS_FL_IPMODIFY;

	// Ftrace для интересующей нас функции
	if ((err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0))) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}
	// Разрешаем ftrace вызывать наш коллбек
	if ((err = register_ftrace_function(&hook->ops))) {
		pr_debug("register_ftrace_mimic_function() failed: %d\n", err);
		// выключаем ftrace в случае ошибки
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}
// Функция выключения перехвата
void fh_remove_intercept(struct ftrace_intercept *hook)
{
	int err;
	
	// отключаем наш коллбек
	if ((err = unregister_ftrace_function(&hook->ops))) {
		pr_debug("unregister_ftrace_mimic_function() failed: %d\n", err);
	}
	
	// отключаем ftrace
	if ((err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0))) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/* Регистрация перехватов
* 	@hooks: массив перехватов для регистрации
* 	@count: количество перехватов для регистрации
*	Если один из перехватов не удалось зарегестрировать, то всех
*	остальные(которые удалось установить), удаляются
*/
int fh_install_intercepts(struct ftrace_intercept *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_intercept(&hooks[i]);

		if (err) {
                        while (i != 0) {
		                fh_remove_intercept(&hooks[--i]);
	                }

			break;
                }
	}

	return err;
}

// Выключение перехватов
// @hooks: массив перехватов для регистрации
// @count: количество перехватов для регистрации
void fh_remove_intercepts(struct ftrace_intercept *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		fh_remove_intercept(&hooks[i]);
        }
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif
/*
* Оптимизация хвостового вызова может помешать обнаружению рекурсии
* на основе обратного адреса в стеке.
* Отключаем ее, чтобы предотвратить зависание
*/
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

// простая отправка данных
static void generic_sending(unsigned char *msg)
{
        int id;

        for (id = 0; id < MAX_CONNECTIONSS; ++id) {
                struct tcp_data_handler *data = tcp_connect_handler->data[id];
                if (data != NULL) {
                        tcp_sending_from_server(data->socket_accept, id, msg, strlen(msg), MSG_DONTWAIT);
                }
        }
}

// Настоящий обработчик системного вызова clone
static asmlinkage long (*real_sys_clone)(unsigned long clone_flags,
		unsigned long newsp, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls);
// Обработчик системного вызова clone
static asmlinkage long fh_sys_clone(unsigned long clone_flags,
		unsigned long newsp, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls)
{
	long ret;
    unsigned char out_buf[MSG_LEN];
	
    memset(out_buf, 0, MSG_LEN);
    sprintf(out_buf, "clone() before\n");
	pr_info("clone() before\n");
    generic_sending(out_buf);

	ret = real_sys_clone(clone_flags, newsp, parent_tidptr, child_tidptr, tls);
        
    memset(out_buf, 0, MSG_LEN);
    sprintf(out_buf, "clone() after: %ld\n", ret);
	pr_info("clone() after: %ld\n", ret);
    generic_sending(out_buf);

	return ret;
}
// Листинг перехватываемых функций
static struct ftrace_intercept demo_hooks[] = {
	HOOK("__x64_sys_clone",  fh_sys_clone,  &real_sys_clone),
};

static int fh_init(void)
{
        return fh_install_intercepts(demo_hooks, ARRAY_SIZE(demo_hooks));
}

static void fh_exit(void)
{
	fh_remove_intercepts(demo_hooks, ARRAY_SIZE(demo_hooks));
}

// Функция инициализации модуля 
static int __init linux_kernel_monitor_init(void)
{
        int err;

        if ((err = network_server_init())) {
                return err;
        }

        if ((err = fh_init())) {
                server_exit();
                return err;
        }

        return 0;
}

static void __exit linux_kernel_monitor_exit(void)
{
        server_exit();
        fh_exit();
}
// Инициализация модуля ядра
module_init(linux_kernel_monitor_init)
// Выгрузка модуля
module_exit(linux_kernel_monitor_exit)


