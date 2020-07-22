#!/bin/sh
#
# Copyright (c) 2019, The Linux Foundation. All rights reserved.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

enable_smp_affinity_wifi() {
	# set smp_affinity for Lithium(ATH11k)
        if [ -d "/sys/kernel/debug/ath11k" ]; then
		irq_affinity_num=`grep -E -m1 'reo2host-destination-ring4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'reo2host-destination-ring3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'reo2host-destination-ring2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'reo2host-destination-ring1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity

		irq_affinity_num=`grep -E -m1 'wbm2host-tx-completions-ring3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'wbm2host-tx-completions-ring2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'wbm2host-tx-completions-ring1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
	fi
}
