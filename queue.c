/**
 * Simple Queue Library
 * Copyright (C) 2011 Ardhan Madras <ajhwb@knac.com>
 *
 * This software is free software; you can redistribute it and/or modify it under 
 * the terms of the GNU General Public License as published by the Free Software 
 * Foundation; version 2 of the License.
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS 
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with 
 * This software; if not, write to the Free Software Foundation, Inc., 51 Franklin 
 * St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <queue.h>
#include <stdlib.h>
#include <string.h>

void queue_init(queue_t **queue)
{
    *queue = NULL;
}

queue_t *queue_append(queue_t *queue, void *data)
{
    queue_t *new_queue;

    new_queue = malloc(sizeof(queue_t));
    if (!new_queue)
        return NULL;

    if (queue) {
        queue_t *ptr = queue;
        while (ptr->next)
            ptr = ptr->next;
        new_queue->data = data;
        new_queue->next = NULL;
        new_queue->prev = ptr;
        ptr->next = new_queue;
        return queue;
    } else {
        new_queue->data = data;
        new_queue->prev = NULL;
        new_queue->next = NULL;
        return new_queue;
    }
}

queue_t *queue_prepend(queue_t *queue, void *data)
{
    if (!queue)
        return queue_append(queue, data);

    queue_t *new_queue;

    new_queue = malloc(sizeof(queue_t));
    new_queue->data = data;
    new_queue->next = queue;
    new_queue->prev = NULL;

    return new_queue;
}

queue_t *queue_remove(queue_t *queue, const void *data)
{
    if (!queue)
        return NULL;

    queue_t *ptr, *prev_list, *next_list;

    for (ptr = queue; ptr; ptr = ptr->next)
        if (ptr->data == data) {

            next_list = ptr->next;
            prev_list = ptr->prev;

            free(ptr);

            if (next_list)
                next_list->prev = prev_list;
            if (prev_list)
                prev_list->next = next_list;
            else
                queue = next_list;

            break;
        }
    return queue;
}

unsigned int queue_length(queue_t *queue)
{
    queue_t *ptr = queue;
    unsigned int retval = 0;

    while (ptr) {
        retval++;
        ptr = ptr->next;
    }
    return retval;
}

queue_t *queue_last(queue_t *queue)
{
    queue_t *ptr = queue;
    if (ptr)
        while (ptr->next)
            ptr = ptr->next;
    return ptr;
}

static queue_t *queue_sort_merge(queue_t *q1, queue_t *q2, 
        int (*func) (const void*, const void*))
{
    queue_t queue, *q, *qprev;
    int cmp;

    q = &queue; 
    qprev = NULL;

    while (q1 && q2) {
        cmp = (func) (q1->data, q2->data);
        if (cmp <= 0) {
            q->next = q1;
            q1 = q1->next;
        } else {
            q->next = q2;
            q2 = q2->next;
        }
        q = q->next;
        q->prev = qprev; 
        qprev = q;
    }
    q->next = q1 ? q1 : q2;
    q->next->prev = q;

    return queue.next;
}

static queue_t *queue_sort_real (queue_t *queue, 
        int (*func) (const void *, const void *))
{
    queue_t *q1, *q2;

    if (!queue)
        return NULL;
    if (!queue->next)
        return queue;

    q1 = queue;
    q2 = queue->next;

    while ((q2 = q2->next) != NULL) {
        if ((q2 = q2->next) == NULL)
            break;
        q1 = q1->next;
    }

    q2 = q1->next;
    q1->next = NULL;

    return queue_sort_merge(queue_sort_real (queue, func), 
                            queue_sort_real (q2, func), func);
}

queue_t *queue_sort(queue_t *list, int (*func) (const void *, const void *))
{
    return queue_sort_real(list, func);
}

queue_t *queue_foreach(queue_t *queue, void (*func) (void *, void *), void *user_data)
{
    queue_t *ptr = queue;

    while (ptr) {
        func(ptr->data, user_data);
        ptr = ptr->next;
    }

    return queue;
}

queue_t *queue_reverse(queue_t *queue)
{
    queue_t *new_queue = NULL;
    queue_t *ptr = queue;

    while (ptr) {
        new_queue = queue_prepend(new_queue, ptr->data);
        ptr = ptr->next;
    }

    return new_queue;
}

