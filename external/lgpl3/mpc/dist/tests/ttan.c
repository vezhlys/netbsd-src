/* ttan -- test file for mpc_tan.

Copyright (C) 2008, 2011, 2012, 2013, 2020 INRIA

This file is part of GNU MPC.

GNU MPC is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the
Free Software Foundation; either version 3 of the License, or (at your
option) any later version.

GNU MPC is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
more details.

You should have received a copy of the GNU Lesser General Public License
along with this program. If not, see http://www.gnu.org/licenses/ .
*/

#include <stdlib.h>
#include "mpc-tests.h"

static void
pure_real_argument (void)
{
  /* tan(x -i*0) = tan(x) -i*0 */
  /* tan(x +i*0) = tan(x) +i*0 */
  mpfr_t x;
  mpfr_t tan_x;
  mpc_t z;
  mpc_t tan_z;

  mpfr_init2 (x, 79);
  mpfr_init2 (tan_x, 113);
  mpc_init2 (z, 79);
  mpc_init2 (tan_z, 113);

  /* tan(1 +i*0) = tan(1) +i*0 */
  mpc_set_ui_ui (z, 1, 0, MPC_RNDNN);
  mpfr_set_ui (x, 1, MPFR_RNDN);
  mpfr_tan (tan_x, x, MPFR_RNDN);
  mpc_tan (tan_z, z, MPC_RNDNN);
  if (mpfr_cmp (mpc_realref (tan_z), tan_x) != 0
      || !mpfr_zero_p (mpc_imagref (tan_z)) || mpfr_signbit (mpc_imagref (tan_z)))
    {
      printf ("mpc_tan(1 + i * 0) failed\n");
      exit (1);
    }

  /* tan(1 -i*0) = tan(1) -i*0 */
  mpc_conj (z, z, MPC_RNDNN);
  mpc_tan (tan_z, z, MPC_RNDNN);
  if (mpfr_cmp (mpc_realref (tan_z), tan_x) != 0
      || !mpfr_zero_p (mpc_imagref (tan_z)) || !mpfr_signbit (mpc_imagref (tan_z)))
    {
      printf ("mpc_tan(1 - i * 0) failed\n");
      exit (1);
    }

  /* tan(Pi/2 +i*0) = +Inf +i*0 */
  mpfr_const_pi (x, MPFR_RNDN);
  mpfr_div_2ui (x, x, 1, MPFR_RNDN);
  mpfr_set (mpc_realref (z), x, MPFR_RNDN);
  mpfr_set_ui (mpc_imagref (z), 0, MPFR_RNDN);
  mpfr_tan (tan_x, x, MPFR_RNDN);
  mpc_tan (tan_z, z, MPC_RNDNN);
  if (mpfr_cmp (mpc_realref (tan_z), tan_x) != 0
      || !mpfr_zero_p (mpc_imagref (tan_z)) || mpfr_signbit (mpc_imagref (tan_z)))
    {
      printf ("mpc_tan(Pi/2 + i * 0) failed\n");
      exit (1);
    }

  /* tan(Pi/2 -i*0) = +Inf -i*0 */
  mpc_conj (z, z, MPC_RNDNN);
  mpc_tan (tan_z, z, MPC_RNDNN);
  if (mpfr_cmp (mpc_realref (tan_z), tan_x) != 0
      || !mpfr_zero_p (mpc_imagref (tan_z)) || !mpfr_signbit (mpc_imagref (tan_z)))
    {
      printf ("mpc_tan(Pi/2 - i * 0) failed\n");
      exit (1);
    }

  /* tan(-Pi/2 +i*0) = -Inf +i*0 */
  mpfr_neg (x, x, MPFR_RNDN);
  mpc_neg (z, z, MPC_RNDNN);
  mpfr_tan (tan_x, x, MPFR_RNDN);
  mpc_tan (tan_z, z, MPC_RNDNN);
  if (mpfr_cmp (mpc_realref (tan_z), tan_x) != 0
      || !mpfr_zero_p (mpc_imagref (tan_z)) || mpfr_signbit (mpc_imagref (tan_z)))
    {
      printf ("mpc_tan(-Pi/2 + i * 0) failed\n");
      exit (1);
    }

  /* tan(-Pi/2 -i*0) = -Inf -i*0 */
  mpc_conj (z, z, MPC_RNDNN);
  mpc_tan (tan_z, z, MPC_RNDNN);
  if (mpfr_cmp (mpc_realref (tan_z), tan_x) != 0
      || !mpfr_zero_p (mpc_imagref (tan_z)) || !mpfr_signbit (mpc_imagref (tan_z)))
    {
      printf ("mpc_tan(-Pi/2 - i * 0) failed\n");
      exit (1);
    }

  mpc_clear (tan_z);
  mpc_clear (z);
  mpfr_clear (tan_x);
  mpfr_clear (x);
}

static void
pure_imaginary_argument (void)
{
  /* tan(-0 +i*y) = -0 +i*tanh(y) */
  /* tan(+0 +i*y) = +0 +i*tanh(y) */
  mpfr_t y;
  mpfr_t tanh_y;
  mpc_t z;
  mpc_t tan_z;
  mpfr_prec_t prec = (mpfr_prec_t) 111;

  mpfr_init2 (y, 2);
  mpfr_init2 (tanh_y, prec);
  mpc_init2 (z, 2);
  mpc_init2 (tan_z, prec);

  /* tan(0 +i) = +0 +i*tanh(1) */
  mpc_set_ui_ui (z, 0, 1, MPC_RNDNN);
  mpfr_set_ui (y, 1, MPFR_RNDN);
  mpfr_tanh (tanh_y, y, MPFR_RNDN);
  mpc_tan (tan_z, z, MPC_RNDNN);
  if (mpfr_cmp (mpc_imagref (tan_z), tanh_y) != 0
      || !mpfr_zero_p (mpc_realref (tan_z)) || mpfr_signbit (mpc_realref (tan_z)))
    {
      mpc_t c99;

      mpc_init2 (c99, prec);
      mpfr_set_ui (mpc_realref (c99), 0, MPFR_RNDN);
      mpfr_set (mpc_imagref (c99), tanh_y, MPFR_RNDN);

      TEST_FAILED ("mpc_tan", z, tan_z, c99, MPC_RNDNN);
    }

  /* tan(0 -i) = +0 +i*tanh(-1) */
  mpc_conj (z, z, MPC_RNDNN);
  mpfr_neg (tanh_y, tanh_y, MPFR_RNDN);
  mpc_tan (tan_z, z, MPC_RNDNN);
  if (mpfr_cmp (mpc_imagref (tan_z), tanh_y) != 0
      || !mpfr_zero_p (mpc_realref (tan_z)) || mpfr_signbit (mpc_realref (tan_z)))
    {
      mpc_t c99;

      mpc_init2 (c99, prec);
      mpfr_set_ui (mpc_realref (c99), 0, MPFR_RNDN);
      mpfr_set (mpc_imagref (c99), tanh_y, MPFR_RNDN);

      TEST_FAILED ("mpc_tan", z, tan_z, c99, MPC_RNDNN);
    }

  /* tan(-0 +i) = -0 +i*tanh(1) */
  mpc_neg (z, z, MPC_RNDNN);
  mpfr_neg (tanh_y, tanh_y, MPFR_RNDN);
  mpc_tan (tan_z, z, MPC_RNDNN);
  if (mpfr_cmp (mpc_imagref (tan_z), tanh_y) != 0
      || !mpfr_zero_p (mpc_realref (tan_z)) || !mpfr_signbit (mpc_realref (tan_z)))
    {
      mpc_t c99;

      mpc_init2 (c99, prec);
      mpfr_set_ui (mpc_realref (c99), 0, MPFR_RNDN);
      mpfr_set (mpc_imagref (c99), tanh_y, MPFR_RNDN);

      TEST_FAILED ("mpc_tan", z, tan_z, c99, MPC_RNDNN);
    }

  /* tan(-0 -i) = -0 +i*tanh(-1) */
  mpc_conj (z, z, MPC_RNDNN);
  mpfr_neg (tanh_y, tanh_y, MPFR_RNDN);
  mpc_tan (tan_z, z, MPC_RNDNN);
  if (mpfr_cmp (mpc_imagref (tan_z), tanh_y) != 0
      || !mpfr_zero_p (mpc_realref (tan_z)) || !mpfr_signbit (mpc_realref (tan_z)))
    {
      mpc_t c99;

      mpc_init2 (c99, prec);
      mpfr_set_ui (mpc_realref (c99), 0, MPFR_RNDN);
      mpfr_set (mpc_imagref (c99), tanh_y, MPFR_RNDN);

      TEST_FAILED ("mpc_tan", z, tan_z, c99, MPC_RNDNN);
    }

  mpc_clear (tan_z);
  mpc_clear (z);
  mpfr_clear (tanh_y);
  mpfr_clear (y);
}

/* test with reduced exponent range */
static void
bug20200211 (void)
{
  mpfr_exp_t emin = mpfr_get_emin ();
  mpc_t x, z, zr;

  mpfr_set_emin (-148);
  mpc_init2 (x, 24);
  mpc_init2 (z, 24);
  mpc_init2 (zr, 24);
  mpfr_set_flt (mpc_realref (x), 0x3.b32d48p24, MPFR_RNDN);
  mpfr_set_flt (mpc_imagref (x), -0x48.08bd0p0, MPFR_RNDN);
  mpc_tan (z, x, MPC_RNDNN);
  /* the real part should be 1.8638349976774607754968796608e-63,
     but since that underflows, we should get +0 */
  mpfr_set_flt (mpc_realref (zr), +0.0f, MPFR_RNDN);
  mpfr_set_flt (mpc_imagref (zr), -1.0f, MPFR_RNDN);
  if (mpc_cmp (z, zr))
    {
      printf ("Incorrect tangent with reduced exponent range:\n");
      mpfr_printf ("Expected (%Re,%Re)\n", mpc_realref (zr), mpc_imagref (zr));
      mpfr_printf ("Got      (%Re,%Re)\n", mpc_realref (z), mpc_imagref (z));
      exit (1);
    }
  mpc_clear (x);
  mpc_clear (z);
  mpc_clear (zr);
  mpfr_set_emin (emin);
}

/* test failing with gcc 5.4.0, line 127 of tan.dat */
static void
bug20200301 (void)
{
  mpc_t x, z, zr;
  int inex;

  mpc_init2 (x, 53);
  mpc_init2 (z, 53);
  mpc_init2 (zr, 53);
  mpfr_set_d (mpc_realref (x), 0x4580CBF242683p-3, MPFR_RNDN);
  mpfr_set_d (mpc_imagref (x), -0x1B3E8A3660D279p-3, MPFR_RNDN);
  inex = mpc_tan (z, x, MPC_RNDNN);
  mpfr_set_d (mpc_realref (zr), -0.0, MPFR_RNDN);
  mpfr_set_d (mpc_imagref (zr), -1.0, MPFR_RNDN);
  if (mpc_cmp (z, zr) != 0 || mpfr_signbit (mpc_realref (z)) == 0 ||
      MPC_INEX_RE(inex) <= 0 || MPC_INEX_IM(inex) >= 0)
    {
      printf ("Incorrect tangent (bug20200301):\n");
      mpfr_printf ("Expected (%Re,%Re)\n", mpc_realref (zr), mpc_imagref (zr));
      mpfr_printf ("Got      (%Re,%Re)\n", mpc_realref (z), mpc_imagref (z));
      mpfr_printf ("expected ternary value (+1, -1)\n");
      mpfr_printf ("got      ternary value (%d, %d)\n", MPC_INEX_RE(inex),
                   MPC_INEX_IM(inex));
      exit (1);
    }
  mpc_clear (x);
  mpc_clear (z);
  mpc_clear (zr);
}

#define MPC_FUNCTION_CALL                                       \
  P[0].mpc_inex = mpc_tan (P[1].mpc, P[2].mpc, P[3].mpc_rnd)
#define MPC_FUNCTION_CALL_REUSE_OP1                             \
  P[0].mpc_inex = mpc_tan (P[1].mpc, P[1].mpc, P[3].mpc_rnd)

#include "data_check.tpl"
#include "tgeneric.tpl"

int
main (void)
{
  test_start ();

  bug20200301 ();
  bug20200211 ();

  data_check_template ("tan.dsc", "tan.dat");

  tgeneric_template ("tan.dsc", 2, 512, 7, 4);

  /* FIXME: remove them? */
  pure_real_argument ();
  pure_imaginary_argument ();

  test_end ();

  return 0;
}
