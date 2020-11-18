#include "monitor_mode.h"

/*****************************************************************************
 *  Function Name     : ringbuf_reset
 *  Description       : This function is used to reset the ringbuffer
 *  Input(s)          : ringbuffer
 *  Output(s)         : reset read and write pointer
 *  Returns           : NIL
 * ***************************************************************************/
void ringbuf_reset(ringbuf_t rb)
{
    rb->wptr = rb->rptr = rb->buf;
}

/*****************************************************************************
 *  Function Name     : ringbuf_is_full
 *  Description       : This function is used to get the ringbuffer
 *                      status
 *  Input(s)          : ringbuffer
 *  Output(s)         : NILL
 *  Returns           : 1 - full
 * ***************************************************************************/
int ringbuf_is_full(const struct ringbuf_t *rb)
{
    return ringbuf_bytes_free(rb) == 0;
}

/*****************************************************************************
 *  Function Name     : ringbuf_new
 *  Description       : This function is used to Create a new ringbuffer
			with the given capacity
 *  Input(s)          : capacity
 *  Output(s)         : NIL
 *  Returns           : new ringbuffer object
 * ***************************************************************************/
ringbuf_t ringbuf_new(size_t capacity)
{
    ringbuf_t rb = malloc(sizeof(struct ringbuf_t));
    if (rb) {

        /* One byte is used for detecting the full condition. */
        rb->size = capacity + 1;
        rb->buf = malloc(rb->size);
        if (rb->buf)
            ringbuf_reset(rb);
        else {
            free(rb);
            return 0;
        }
    }
    return rb;
}

/*****************************************************************************
 *  Function Name     : ringbuf_buffer_size
 *  Description       : This function is used to get the ringbuffer size
 *
 *  Input(s)          : ringbuffer
 *  Output(s)         : NIL
 *  Returns           : size of the ringbuffer
 * ***************************************************************************/
size_t ringbuf_buffer_size(const struct ringbuf_t *rb)
{
    return rb->size;
}

/*****************************************************************************
 *  Function Name     : ringbuf_capacity
 *  Description       : This function is used to
 *
 *  Input(s)          : ringbuffer
 *  Output(s)         : NIL
 *  Returns           : capacity of the ringbuffer
 * ***************************************************************************/
size_t ringbuf_capacity(const struct ringbuf_t *rb)
{
    return ringbuf_buffer_size(rb) - 1;
}

/*****************************************************************************
 *  Function Name     : ringbuf_del
 *  Description       : This function is used to delete the ringbuffer
 *
 *  Input(s)          : ringbuffer
 *  Output(s)         : NIL
 *  Returns           : NIL
 * ***************************************************************************/
void ringbuf_del(ringbuf_t *rb)
{
    assert(rb && *rb);
    free((*rb)->buf);
    free(*rb);
}

/*****************************************************************************
 *  Function Name     : ringbuf_end
 *  Description       : This function is used to get the ringbuffer end
 *                      pointer
 *  Input(s)          : ringbuffer
 *  Output(s)         : NIL
 *  Returns           : ringbuffer end pointer
 * ***************************************************************************/
const uint8_t *ringbuf_end(const struct ringbuf_t *rb)
{
    return rb->buf + ringbuf_buffer_size(rb);
}

/*****************************************************************************
 *  Function Name     : ringbuf_bytes_free
 *  Description       : This function is used to get the free bytes available
 *                      in the ringbuffer
 *  Input(s)          : ringbuffer
 *  Output(s)         : NIL
 *  Returns           : free bytes
 * ***************************************************************************/
size_t ringbuf_bytes_free(const struct ringbuf_t *rb)
{
    if (rb->wptr >= rb->rptr)
        return ringbuf_capacity(rb) - (rb->wptr - rb->rptr);
    else
        return rb->rptr - rb->wptr - 1;
}

/*****************************************************************************
 *  Function Name     : ringbuf_bytes_used
 *  Description       : This function is used to get the used bytes in the
 *                      ringbuffer
 *  Input(s)          : ringbuffer
 *  Output(s)         : NIL
 *  Returns           : used bytes
 * ***************************************************************************/
size_t ringbuf_bytes_used(const struct ringbuf_t *rb)
{
    return ringbuf_capacity(rb) - ringbuf_bytes_free(rb);
}

/*****************************************************************************
 *  Function Name     : ringbuf_write_buffer
 *  Description       : This function is used to write the data into
 *                      ringbuffer
 *  Input(s)          : ringbuffer, source address, count
 *  Output(s)         : update read and write pointer address
 *  Returns           : next byte write address
 * ***************************************************************************/
void *ringbuf_write_buffer(ringbuf_t rb, const uint8_t *src, size_t count)
{
    const uint8_t *bufend = ringbuf_end(rb);

    size_t nwritten = 0;
    while (nwritten != count) {
        /* don't copy beyond the end of the buffer */
        assert(bufend > rb->wptr);
        size_t n = MIN(bufend - rb->wptr, count - nwritten);
        memcpy(rb->wptr, src + nwritten, n);
        rb->wptr += n;
        nwritten += n;

        /* wrap? */
        if (rb->wptr == bufend)
            rb->wptr = rb->buf;
    }

    return rb->wptr;
}

/*****************************************************************************
 *  Function Name     : ringbuf_read_buffer
 *  Description       : This function is used to read the data from
 *                      ringbuffer
 *  Input(s)          : ringbuffer, destination address, count
 *  Output(s)         : update read pointer address
 *  Returns           : next byte read address
 * ***************************************************************************/
void *ringbuf_read_buffer(ringbuf_t rb, uint8_t *dst, size_t count)
{
    size_t bytes_used = ringbuf_bytes_used(rb);
    if (count > bytes_used)
        return 0;

    const uint8_t *bufend = ringbuf_end(rb);
    size_t nread = 0;
    while (nread != count) {
        assert(bufend > rb->rptr);
        size_t n = MIN(bufend - rb->rptr, count - nread);
        memcpy(dst + nread, rb->rptr, n);
        rb->rptr += n;
        nread += n;

        /* wrap ? */
        if (rb->rptr == bufend)
            rb->rptr = rb->buf;
    }

    assert(count + ringbuf_bytes_used(rb) == bytes_used);
    return rb->rptr;
}

/*****************************************************************************
 *  Function Name     : ringbuf_discard
 *  Description       : This function is used to discard the data from the
 *                      ringbuffer
 *  Input(s)          : ringbuffer, count
 *  Output(s)         : update read pointer address
 *  Returns           : NIL
 * ***************************************************************************/
void ringbuf_discard(ringbuf_t rb, size_t count)
{
    const uint8_t *bufend = ringbuf_end(rb);

    if ( (rb->rptr + count) < bufend)
        rb->rptr += count;
    else
        rb->rptr = rb->buf + count - (bufend - rb->rptr);
}
