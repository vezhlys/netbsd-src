/*	$NetBSD: msg_244.c,v 1.5 2025/04/12 15:49:50 rillig Exp $	*/
# 3 "msg_244.c"

// Test for message: invalid structure pointer combination [244]

/* lint1-extra-flags: -X 351 */

struct a {
	int member;
};

struct b {
	int member;
};

int
diff(struct a *a, struct b *b)
{
	/* expect+1: error: invalid pointer subtraction [116] */
	return a - b;
}

_Bool
lt(struct a *a, struct b *b)
{
	/* expect+1: warning: incompatible structure pointers: 'pointer to struct a' '<' 'pointer to struct b' [245] */
	return a < b;
}

struct a *
ret(struct b *b)
{
	/* expect+1: warning: invalid structure pointer combination [244] */
	return b;
}
