// SPDX-License-Identifier: GPL-2.0-only
/* 单线程运行实际 Linux IDR 和从候选源提取的分配函数；不模拟网络或并发锁。 */
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include "test.h"

struct ktcp_cb {
	struct idr transactions;
	int error;
	int rlock;
};

/* 只测单线程编号空间，锁和无法到达的网络中止分支不参与此项验收。 */
#define mutex_lock_killable(lock) 0
#define mutex_unlock(lock) ((void)0)
#define ktcp_abort(cb, error) (error)
#include "sshpool-ktcp-allocator.inc"

int main(void)
{
	struct ktcp_cb cb = {};
	struct ktcp_transaction *transactions;
	bool seen[65536] = {};
	int i, ret;

	setbuf(stdout, NULL);
	rcu_register_thread();
	radix_tree_init();
	idr_init(&cb.transactions);
	transactions = calloc(65536, sizeof(*transactions));
	assert(transactions);
	for (i = 0; i < 65535; i++) {
		ret = ktcp_begin_transaction(&cb, NULL, &transactions[i]);
		assert(ret == 0);
		assert(transactions[i].id != 255);
		assert(!seen[transactions[i].id]);
		assert(idr_find(&cb.transactions, transactions[i].id) == &transactions[i]);
		seen[transactions[i].id] = true;
	}
	printf("allocated=65535 unique=65535 reserved_unused=1\n");
	ret = ktcp_begin_transaction(&cb, NULL, &transactions[65535]);
	assert(ret == -ENOSPC);
	assert(!idr_find(&cb.transactions, 255));
	printf("exhaustion_errno=%d reserved_unused=1\n", -ret);
	assert(idr_remove(&cb.transactions, 40000));
	ret = ktcp_begin_transaction(&cb, NULL, &transactions[65535]);
	assert(ret == 0 && transactions[65535].id == 40000);
	assert(idr_find(&cb.transactions, 40000) == &transactions[65535]);
	printf("reclaimed_id=40000 reused_id=40000\n");
	for (i = 0; i < 65536; i++) {
		if (i != 255)
			assert(idr_remove(&cb.transactions, i));
	}
	assert(idr_is_empty(&cb.transactions));
	idr_destroy(&cb.transactions);
	free(transactions);
	radix_tree_cpu_dead(1);
	rcu_barrier();
	assert(nr_allocated == 0);
	rcu_unregister_thread();
	printf("all_transactions_removed=1 allocator_nodes_remaining=0\n");
	return 0;
}
