/*	$NetBSD: decl_enum.c,v 1.6 2024/10/29 20:48:31 rillig Exp $	*/
# 3 "decl_enum.c"

/*
 * Tests for enum declarations.
 */


// Initializing an enum from a 64-bit value cuts off the upper bits.
// TIME_MIN thus gets truncated from 0x8000_0000_0000_0000 to 0.
// TIME_MAX thus gets truncated from 0x7fff_ffff_ffff_ffff to -1.
enum {
	/* expect+1: warning: constant -0x8000000000000000 too large for 'int' [56] */
	TIME_MIN = (long long)(1ULL << 63),
	/* expect+1: warning: constant 0x7fffffffffffffff too large for 'int' [56] */
	TIME_MAX = (long long)~(1ULL << 63),
};


/* cover 'enumerator_list: error' */
enum {
	/* expect+1: error: syntax error 'goto' [249] */
	goto
};

/* cover 'enum_specifier: enum error' */
/* expect+1: error: syntax error 'goto' [249] */
enum goto {
	A
};
/* expect-1: warning: empty declaration [0] */


/*
 * Ensure that nested enum declarations get the value of each enum constant
 * right.  The variable containing the "current enum value" does not account
 * for these nested declarations.  Such declarations don't occur in practice
 * though.
 */
enum outer {
	o1 = sizeof(
	    enum inner {
		    i1 = 10000, i2, i3
	    }
	),
	/*
	 * The only attribute that GCC 12 allows for enum constants is
	 * __deprecated__, and there is no way to smuggle an integer constant
	 * expression into the attribute.  If there were a way, and the
	 * expression contained an enum declaration, the value of the outer
	 * enum constant would become the value of the last seen inner enum
	 * constant.  This is because 'enumval' is a simple scalar variable,
	 * not a stack.  If it should ever become necessary to account for
	 * nested enum declarations, a field should be added in decl_level.
	 */
	o2 __attribute__((__deprecated__)),
	o3 = i3
};

/* expect+1: error: negative array dimension (-10000) [20] */
typedef int reveal_i1[-i1];
/* expect+1: error: negative array dimension (-10001) [20] */
typedef int reveal_i2[-i2];
/* expect+1: error: negative array dimension (-10002) [20] */
typedef int reveal_i3[-i3];

/* expect+1: error: negative array dimension (-4) [20] */
typedef int reveal_o1[-o1];
/* expect+1: error: negative array dimension (-5) [20] */
typedef int reveal_o2[-o2];
/* expect+1: error: negative array dimension (-10002) [20] */
typedef int reveal_o3[-o3];

/* Since C99, a trailing comma is allowed in an enum declaration. */
enum trailing_comma {
	constant,
};
