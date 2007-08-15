/*
 * This is endianness detection module for CNTLM
 *
 * CNTLM is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * CNTLM is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
 * St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Copyright (c) 2007 David Kubicek
 *
 */

#include <stdio.h>
#include <stdint.h>

uint8_t num[] = { 0xEF, 0xBE };

/*
 * No output on LE. Prints "-DBIG_ENDIAN" or if $1 not empty "-D$1" on BE.
 * Lame :)
 */
int main(int argc, char **argv) {

	if (*((uint16_t *)num) != 0xBEEF)
		printf("-D%s\n", argc > 1 ? argv[1] : "BIG_ENDIAN");

	return 0;
}
