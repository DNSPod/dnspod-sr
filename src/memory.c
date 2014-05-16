/* Copyright (c) 2006-2012, DNSPod Inc.
 * All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of the FreeBSD Project.
 */



#include "memory.h"

struct mbuf_ring *mbuf_ring = NULL;

/* create the ring */
struct mbuf_ring *
mbuf_ring_create(uint32_t count)
{
    struct mbuf_ring *r;
    uint64_t ring_size;

    ring_size = count * sizeof(void *) + sizeof(struct mbuf_ring);

    r = (struct mbuf_ring *)malloc(ring_size);
    if (r != NULL) {
        memset(r, 0, sizeof(struct mbuf_ring));
        r->prod.watermark = count;
        r->prod.size = r->cons.size = count;
        r->prod.mask = r->cons.mask = count - 1;
        r->prod.head = r->cons.head = 0;
        r->prod.tail = r->cons.tail = 0;
    }
    
    return r;
}

int
mempool_create(uint32_t num)
{
    mbuf_type *tmp;
    int i;
    
    mbuf_ring = mbuf_ring_create(num);
    if (NULL == mbuf_ring)
        return -1;
    
    for (i = 0; i < num; i++)
    {
        tmp = (mbuf_type *)malloc(sizeof(mbuf_type));
        if (NULL == tmp)
            return -1;
        
        tmp->mbuf = mbuf_ring;
        mbuf_ring->ring[i] = tmp;
    }
    mbuf_ring->prod.head = mbuf_ring->prod.tail = num - 1;
    
    return 0;
}

#define mbuf_compiler_barrier() do {     \
    asm volatile ("" : : : "memory");   \
} while(0)

static inline int
rte_atomic32_cmpset(volatile uint32_t *dst, uint32_t exp, uint32_t src)
{
    uint8_t res;

    asm volatile(
            "lock ; "
            "cmpxchgl %[src], %[dst];"
            "sete %[res];"
            : [res] "=a" (res),     /* output */
              [dst] "=m" (*dst)
            : [src] "r" (src),      /* input */
              "a" (exp),
              "m" (*dst)
            : "memory");            /* no-clobber list */
    return res;
}

mbuf_type *
mbuf_alloc()
{
    uint32_t cons_head, prod_tail;
    uint32_t cons_next, entries;
    int success;
    uint32_t mask = mbuf_ring->prod.mask;
    mbuf_type *mbuf;

    cons_head = mbuf_ring->cons.head;
    prod_tail = mbuf_ring->prod.tail;

    entries = (prod_tail - cons_head);
    if (0 == entries)
        return NULL;

    cons_next = cons_head + 1;
    success = rte_atomic32_cmpset(&mbuf_ring->cons.head, cons_head, cons_next);
    if (success != 1)
        return NULL;

    /* copy in table */
    mbuf = mbuf_ring->ring[cons_head & mask];
    assert(mbuf != NULL);
    mbuf_compiler_barrier();
    while (mbuf_ring->cons.tail != cons_head);

    mbuf_ring->cons.tail = cons_next;

    return mbuf;
}

int
mbuf_free(mbuf_type *mbuf)
{
    uint32_t prod_head, prod_next;
    uint32_t cons_tail, free_entries;
    int success;
    uint32_t mask = mbuf_ring->prod.mask;

    if (NULL == mbuf)
        return 0;
    
    /* move prod.head atomically */
    do {
        prod_head = mbuf_ring->prod.head;
        cons_tail = mbuf_ring->cons.tail;

        free_entries = (mask + cons_tail - prod_head);
        assert(free_entries > 0);

        prod_next = prod_head + 1;
        success = rte_atomic32_cmpset(&mbuf_ring->prod.head, prod_head, prod_next);
    } while (0 == success);

    /* write entries in ring */
    mbuf_ring->ring[prod_head & mask] = mbuf;
    mbuf_compiler_barrier();

    while (mbuf_ring->prod.tail != prod_head);
    mbuf_ring->prod.tail = prod_next;
    
    return 0;
}