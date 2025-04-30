#include "vmlinux.h"

struct mm_struct ** task_struct_mm(struct task_struct *task) {
	return __builtin_preserve_access_index(&task->mm);
}

