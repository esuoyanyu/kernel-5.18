# [do_select](http://gitlab.esuoyanyu.com/kernel/common/-/tree/main/fs/select.c)
```
static int do_select(int n, fd_set_bits *fds, struct timespec64 *end_time)
{
	struct poll_wqueues table;
	poll_table *wait;
	__poll_t busy_flag = net_busy_loop_on() ? POLL_BUSY_LOOP : 0;
        /*找到位图的最大值*/
	retval = max_select_fd(n, fds);

	n = retval;
        
        /* 初始化工作队列项 */
	poll_initwait(&table);
	wait = &table.pt;

	for (;;) {
		unsigned long *rinp, *routp, *rexp, *inp, *outp, *exp;
		bool can_busy_loop = false;

		inp = fds->in; outp = fds->out; exp = fds->ex;
		rinp = fds->res_in; routp = fds->res_out; rexp = fds->res_ex;
                /*遍历位图*/
		for (i = 0; i < n; ++rinp, ++routp, ++rexp) {
			unsigned long in, out, ex, all_bits, bit = 1, j;
			unsigned long res_in = 0, res_out = 0, res_ex = 0;
			__poll_t mask;

			in = *inp++; out = *outp++; ex = *exp++;
			all_bits = in | out | ex;
			if (all_bits == 0) {
				i += BITS_PER_LONG;
				continue;
			}
                        /*根据字长的遍历位图，如果有数据到来，则置位，并保存到rxxp中*/
			for (j = 0; j < BITS_PER_LONG; ++j, ++i, bit <<= 1) { #
				struct fd f;
				if (i >= n)
					break;
				if (!(bit & all_bits))
					continue;
				mask = EPOLLNVAL;
				f = fdget(i);
				if (f.file) {
					wait_key_set(wait, in, out, bit,
						     busy_flag);
					/* 调用驱动程序的poll, 通过poll_wait把wait挂到驱动程序的等待队列的头上 */
                                        mask = vfs_poll(f.file, wait);
                                        fdput(f);
				}
                                /* 检查监听的文件是否有数据到来*/
				if ((mask & POLLIN_SET) && (in & bit)) {
					res_in |= bit;
					retval++;
					wait->_qproc = NULL;
				}
				if ((mask & POLLOUT_SET) && (out & bit)) {
					res_out |= bit;
					retval++;
					wait->_qproc = NULL;
				}
				if ((mask & POLLEX_SET) && (ex & bit)) {
					res_ex |= bit;
					retval++;
					wait->_qproc = NULL;
				}
				/* got something, stop busy polling */
				if (retval) {
					can_busy_loop = false;
					busy_flag = 0;

				/*
				 * only remember a returned
				 * POLL_BUSY_LOOP if we asked for it
				 */
				} else if (busy_flag & mask)
					can_busy_loop = true;

			}
			if (res_in)
				*rinp = res_in;
			if (res_out)
				*routp = res_out;
			if (res_ex)
				*rexp = res_ex;
                        /*主动让出cpu,让其他线程得到执行*/
			cond_resched();
		}
		wait->_qproc = NULL;
                /*如果有数据到来、超时、有信号到来则结束*/
		if (retval || timed_out || signal_pending(current))
			break;

                /* 把等待数据的进程挂起，直到超时，或有数据到来，被唤醒 */
		if (!poll_schedule_timeout(&table, TASK_INTERRUPTIBLE,
					   to, slack))
			timed_out = 1;
	}

	poll_freewait(&table);

	return retval;
}
```

## [poll_initwait](http://gitlab.esuoyanyu.com/kernel/common/-/tree/main/include/linux/poll.h)
```
void poll_initwait(struct poll_wqueues *pwq)
{
        /*把__poll_wait注册进去*/
	init_poll_funcptr(&pwq->pt, __pollwait);
        /*保存当前进程task_struct,为将来唤醒准备*/
	pwq->polling_task = current;
	pwq->triggered = 0;
	pwq->error = 0;
	pwq->table = NULL;
	pwq->inline_index = 0;
}
```
### [init_poll_funcptr](http://gitlab.esuoyanyu.com/kernel/common/-/tree/main/include/linux/poll.h)
```
void init_poll_funcptr(poll_table *pt, poll_queue_proc qproc)
{
	pt->_qproc = qproc;
	pt->_key   = ~(__poll_t)0; /* all events enabled */
}
```
### [__pollwait](common/fs/select.c)
```
static void __pollwait(struct file *filp, wait_queue_head_t *wait_address,
				poll_table *p)
{
	struct poll_wqueues *pwq = container_of(p, struct poll_wqueues, pt);
	struct poll_table_entry *entry = poll_get_entry(pwq);
	if (!entry)
		return;
	entry->filp = get_file(filp);
	entry->wait_address = wait_address;
	entry->key = p->_key;
        /*初始化等待队列项， 唤醒后调用pollwake函数*/
	init_waitqueue_func_entry(&entry->wait, pollwake);
	entry->wait.private = pwq;
        /*把等待队列项添加到等待队列头*/
	add_wait_queue(wait_address, &entry->wait);
}
```
### [pollwake](common/fs/select.c)
```
int pollwake(wait_queue_entry_t *wait, unsigned mode, int sync, void *key)
{
	struct poll_table_entry *entry;

	entry = container_of(wait, struct poll_table_entry, wait);
	if (key && !(key_to_poll(key) & entry->key))
		return 0;
	return __pollwake(wait, mode, sync, key);
}
```
### [__pollwake](common/fs/select.c)
```
static int __pollwake(wait_queue_entry_t *wait, unsigned mode, int sync, void *key)
{
	struct poll_wqueues *pwq = wait->private;
        /*初始化等待队列，即利用等待队列唤醒等待的进程*/
	DECLARE_WAITQUEUE(dummy_wait, pwq->polling_task);

	/*
	 * Although this function is called under waitqueue lock, LOCK
	 * doesn't imply write barrier and the users expect write
	 * barrier semantics on wakeup functions.  The following
	 * smp_wmb() is equivalent to smp_wmb() in try_to_wake_up()
	 * and is paired with smp_store_mb() in poll_schedule_timeout.
	 */
	smp_wmb();
	pwq->triggered = 1;

	/*
	 * Perform the default wake up operation using a dummy
	 * waitqueue.
	 *
	 * TODO: This is hacky but there currently is no interface to
	 * pass in @sync.  @sync is scheduled to be removed and once
	 * that happens, wake_up_process() can be used directly.
	 */
         /*唤醒等待队列*/
	return default_wake_function(&dummy_wait, mode, sync, key);
}
```

## [poll_schedule_timeout](common/fs/select.c)
```
int poll_schedule_timeout(struct poll_wqueues *pwq, int state,
			  ktime_t *expires, unsigned long slack)
{
	int rc = -EINTR;

        /*设置进程状态为睡眠并可被中断打断*/
	set_current_state(state);

        /*如果没有被唤醒，调度其他进程运行*/
	if (!pwq->triggered)
		rc = schedule_hrtimeout_range(expires, slack, HRTIMER_MODE_ABS);

        /*醒来后这只进程状态为可运行*/
	__set_current_state(TASK_RUNNING);

	/*
	 * Prepare for the next iteration.
	 *
	 * The following smp_store_mb() serves two purposes.  First, it's
	 * the counterpart rmb of the wmb in pollwake() such that data
	 * written before wake up is always visible after wake up.
	 * Second, the full barrier guarantees that triggered clearing
	 * doesn't pass event check of the next iteration.  Note that
	 * this problem doesn't exist for the first iteration as
	 * add_wait_queue() has full barrier semantics.
	 */
	smp_store_mb(pwq->triggered, 0);

	return rc;
}
```

## [poll_wait](common/include/linux/poll.h)
```
/*驱动程序调用，把等待队列项加入到等待队列头中*/
void poll_wait(struct file * filp, wait_queue_head_t * wait_address, poll_table *p)
{
	if (p && p->_qproc && wait_address)
		p->_qproc(filp, wait_address, p);
}
```
