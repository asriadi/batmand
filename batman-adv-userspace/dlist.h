/*
 * Copyright (C) 2007 B.A.T.M.A.N. contributors:
 * Simon Wunderlich
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 * ddlist.h
 */

#ifndef _LINUX_DLIST_H
#define _LINUX_DLIST_H

/*
 * XXX: Resolve conflict between this file and <sys/queue.h> on BSD systems.
 */
#ifdef DLIST_HEAD
#undef DLIST_HEAD
#endif

/*
 * Simple doubly linked dlist implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole dlists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

struct dlist_head {
	struct dlist_head *next, *prev;
};
#define DLIST_HEAD_INIT(name) { &(name), &(name) }

#define DLIST_HEAD(name) \
	struct dlist_head name = DLIST_HEAD_INIT(name)

#define INIT_DLIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal dlist manipulation where we know
 * the prev/next entries already!
 */
static inline void __dlist_add(struct dlist_head *new,
			      struct dlist_head *prev,
			      struct dlist_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

/**
 * dlist_add - add a new entry
 * @new: new entry to be added
 * @head: dlist head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void dlist_add(struct dlist_head *new, struct dlist_head *head)
{
	__dlist_add(new, head, head->next);
}

/**
 * dlist_add_tail - add a new entry
 * @new: new entry to be added
 * @head: dlist head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void dlist_add_tail(struct dlist_head *new, struct dlist_head *head)
{
	__dlist_add(new, head->prev, head);
}

/*
 * Delete a dlist entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal dlist manipulation where we know
 * the prev/next entries already!
 */
static inline void __dlist_del(struct dlist_head *prev, struct dlist_head *next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * dlist_del - deletes entry from dlist.
 * @entry: the element to delete from the dlist.
 * Note: dlist_empty on entry does not return true after this, the entry is in an undefined state.
 */
static inline void dlist_del(struct dlist_head *entry)
{
	__dlist_del(entry->prev, entry->next);
	entry->next = (void *) 0;
	entry->prev = (void *) 0;
}

static inline void dlist_add_before( struct dlist_head *dlist, struct dlist_head *pos_node, struct dlist_head *new_node ) {

	if ( pos_node->prev != NULL )
		pos_node->prev->next = new_node;
	else
		dlist->next = new_node;

	new_node->prev = pos_node->prev;
	new_node->next = pos_node;

	pos_node->prev = new_node;

}

/**
 * dlist_del_init - deletes entry from dlist and reinitialize it.
 * @entry: the element to delete from the dlist.
 */
static inline void dlist_del_init(struct dlist_head *entry)
{
	__dlist_del(entry->prev, entry->next);
	INIT_DLIST_HEAD(entry);
}

/**
 * dlist_move - delete from one dlist and add as another's head
 * @dlist: the entry to move
 * @head: the head that will precede our entry
 */
static inline void dlist_move(struct dlist_head *dlist, struct dlist_head *head)
{
        __dlist_del(dlist->prev, dlist->next);
        dlist_add(dlist, head);
}

/**
 * dlist_move_tail - delete from one dlist and add as another's tail
 * @dlist: the entry to move
 * @head: the head that will follow our entry
 */
static inline void dlist_move_tail(struct dlist_head *dlist,
				  struct dlist_head *head)
{
        __dlist_del(dlist->prev, dlist->next);
        dlist_add_tail(dlist, head);
}

/**
 * dlist_empty - tests whether a dlist is empty
 * @head: the dlist to test.
 */
static inline int dlist_empty(struct dlist_head *head)
{
	return head->next == head;
}

static inline void __dlist_splice(struct dlist_head *dlist,
				 struct dlist_head *head)
{
	struct dlist_head *first = dlist->next;
	struct dlist_head *last = dlist->prev;
	struct dlist_head *at = head->next;

	first->prev = head;
	head->next = first;

	last->next = at;
	at->prev = last;
}

/**
 * dlist_splice - join two dlists
 * @dlist: the new dlist to add.
 * @head: the place to add it in the first dlist.
 */
static inline void dlist_splice(struct dlist_head *dlist, struct dlist_head *head)
{
	if (!dlist_empty(dlist))
		__dlist_splice(dlist, head);
}

/**
 * dlist_splice_init - join two dlists and reinitialise the emptied dlist.
 * @dlist: the new dlist to add.
 * @head: the place to add it in the first dlist.
 *
 * The dlist at @dlist is reinitialised
 */
static inline void dlist_splice_init(struct dlist_head *dlist,
				    struct dlist_head *head)
{
	if (!dlist_empty(dlist)) {
		__dlist_splice(dlist, head);
		INIT_DLIST_HEAD(dlist);
	}
}

/**
 * dlist_entry - get the struct for this entry
 * @ptr:	the &struct dlist_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the dlist_struct within the struct.
 */
#define dlist_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

/**
 * dlist_for_each	-	iterate over a dlist
 * @pos:	the &struct dlist_head to use as a loop counter.
 * @head:	the head for your dlist.
 */
#define dlist_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); \
        	pos = pos->next)
/**
 * dlist_for_each_prev	-	iterate over a dlist backwards
 * @pos:	the &struct dlist_head to use as a loop counter.
 * @head:	the head for your dlist.
 */
#define dlist_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); \
        	pos = pos->prev)

/**
 * dlist_for_each_safe	-	iterate over a dlist safe against removal of dlist entry
 * @pos:	the &struct dlist_head to use as a loop counter.
 * @n:		another &struct dlist_head to use as temporary storage
 * @head:	the head for your dlist.
 */
#define dlist_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

/**
 * dlist_for_each_entry	-	iterate over dlist of given type
 * @pos:	the type * to use as a loop counter.
 * @head:	the head for your dlist.
 * @member:	the name of the dlist_struct within the struct.
 */
#define dlist_for_each_entry(pos, head, member)				\
	for (pos = dlist_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = dlist_entry(pos->member.next, typeof(*pos), member))

/**
 * dlist_for_each_entry_safe - iterate over dlist of given type safe against removal of dlist entry
 * @pos:	the type * to use as a loop counter.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your dlist.
 * @member:	the name of the dlist_struct within the struct.
 */
#define dlist_for_each_entry_safe(pos, n, head, member)			\
	for (pos = dlist_entry((head)->next, typeof(*pos), member),	\
		n = dlist_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = dlist_entry(n->member.next, typeof(*n), member))

/**
 * dlist_for_each_entry_continue -       iterate over dlist of given type
 *                      continuing after existing point
 * @pos:        the type * to use as a loop counter.
 * @head:       the head for your dlist.
 * @member:     the name of the dlist_struct within the struct.
 */
#define dlist_for_each_entry_continue(pos, head, member)			\
	for (pos = dlist_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = dlist_entry(pos->member.next, typeof(*pos), member))

#endif

