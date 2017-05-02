#ifndef PERFORMANCECOUNTERS_H_
#define PERFORMANCECOUNTERS_H_

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu,
		int group_fd, unsigned long flags) {
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

int get_fd_perf_counter(int type, int config) {
	struct perf_event_attr pe;
	int fd;

	memset(&pe, 0, sizeof(struct perf_event_attr));
	pe.type = type;
	pe.size = sizeof(struct perf_event_attr);
	pe.config = config;
	// starts disabled, the event is later enabled by ioctl
	pe.disabled = 0;
	// count events of child tasks as well as the task specified
	pe.inherit = 1;
	// counter should always be on the CPU
	pe.pinned = 1;
	// it does not exclude events that happen in kernel-space
	pe.exclude_kernel = 0;
	// it does not exclude events that happen in the hypervisor
	pe.exclude_hv = 0;

	fd = perf_event_open(&pe, 0, -1, -1, 0);
	if (fd == -1) {
		handle_error("Error opening perf counter");
	}
	return fd;
}

void start_perf_counter(int fd) {
	int rc;

	rc = ioctl(fd, PERF_EVENT_IOC_RESET, 0);
	if (rc != 0)
		handle_error("Error reseting perf_counter, fd");
	rc = ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	if (rc != 0)
		handle_error("Error enabling perf_counter, fd");
}

unsigned int stop_perf_counter(int fd) {
	int rc;
	long long perfcounter;

	rc = ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
	if (rc != 0)
		handle_error("Error disabling perf_counter, fd");
	if (read(fd, &perfcounter, sizeof(perfcounter)) != sizeof(long long)) {
		handle_error("Error read perf_counter, fd");
	}
	return perfcounter;
}

#endif /* PERFORMANCECOUNTERS_H_ */
