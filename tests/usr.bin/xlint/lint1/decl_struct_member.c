/*	$NetBSD: decl_struct_member.c,v 1.20 2025/04/12 15:49:49 rillig Exp $	*/
# 3 "decl_struct_member.c"

/* lint1-extra-flags: -X 351 */

struct multi_attributes {
	__attribute__((deprecated))
	__attribute__((deprecated))
	__attribute__((deprecated))
	int deprecated;
};

struct cover_begin_type_specifier_qualifier_list {
	int m1;
	__attribute__((deprecated)) int m2;
	const int m3;
	int const m4;
	int const long m5;
	int __attribute__((deprecated)) m6;
};

typedef int number;

struct cover_begin_type_typespec {
	int m1;
	number m2;
};

struct cover_begin_type_qualifier_list {
	const m1;
	const volatile m2;
};

/* cover struct_or_union_specifier: struct_or_union error */
/* expect+1: error: syntax error 'goto' [249] */
struct goto {
	/* expect+1: error: invalid type combination [4] */
	int member;
	/* expect+1: error: syntax error '}' [249] */
};
/* expect-1: warning: empty declaration [0] */

/*
 * Before cgram.y 1.228 from 2021-06-19, lint ran into an assertion failure:
 *
 * "is_struct_or_union(dcs->d_type->t_tspec)" at cgram.y:846
 */
struct {
	/* expect+1: error: syntax error 'unnamed member' [249] */
	char;
};

struct cover_notype_struct_declarators {
	const a, b;
};

struct cover_notype_struct_declarator_bit_field {
	const a:3, :0, b:4;
	const:0;
};

/*
 * An array of bit-fields sounds like a strange idea since a bit-field member
 * is not addressable, while an array needs to be addressable.  Due to this
 * contradiction, this combination may have gone without mention in the C
 * standards.
 *
 * GCC 10.3.0 complains that the bit-field has invalid type.
 *
 * Clang 12.0.1 complains that the bit-field has non-integral type 'unsigned
 * int [8]'.
 */
struct array_of_bit_fields {
	/* expect+1: warning: invalid bit-field type 'array[8] of unsigned int' [35] */
	unsigned int bits[8]: 1;
};

/*
 * Before decl.c 1.188 from 2021-06-20, lint ran into a segmentation fault.
 */
struct {
	/* expect+1: error: syntax error '0' [249] */
	char a(_)0

/*
 * Before cgram.y 1.328 from 2021-07-15, lint ran into an assertion failure
 * at the closing semicolon:
 *
 * assertion "t == NO_TSPEC" failed in end_type at decl.c:774
 */
};
/* expect+1: error: cannot recover from previous errors [224] */
