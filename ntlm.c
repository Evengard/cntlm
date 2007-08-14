/*
 * These are NTLM authentication routines for the main module of CNTLM
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

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "ntlm.h"
#include "swap.h"
#include "xcrypt.h"
#include "utils.h"

extern int debug;

static void ntlm_set_key(unsigned char *src, gl_des_ctx *context) {
	char key[8];

	key[0] = src[0];
	key[1] = ((src[0] << 7) & 0xff) | (src[1] >> 1);
	key[2] = ((src[1] << 6) & 0xff) | (src[2] >> 2);
	key[3] = ((src[2] << 5) & 0xff) | (src[3] >> 3);
	key[4] = ((src[3] << 4) & 0xff) | (src[4] >> 4);
	key[5] = ((src[4] << 3) & 0xff) | (src[5] >> 5);
	key[6] = ((src[5] << 2) & 0xff) | (src[6] >> 6);
	key[7] = (src[6] << 1) & 0xff;

	gl_des_setkey(context, key);
}

static void ntlm_calc_resp(char *dst, char *keys, char *challenge) {
	gl_des_ctx context;

	ntlm_set_key(MEM(keys, unsigned char, 0), &context);
	gl_des_ecb_encrypt(&context, challenge, dst);

	ntlm_set_key(MEM(keys, unsigned char, 7), &context);
	gl_des_ecb_encrypt(&context, challenge, dst+8);

	ntlm_set_key(MEM(keys, unsigned char, 14), &context);
	gl_des_ecb_encrypt(&context, challenge, dst+16);
}

static void ntlm_lm_password(char *dst, char *password, char *challenge) {
	char magic[8] = {0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
	gl_des_ctx context;
	char *keys, *pass;

	keys = new(24);
	pass = new(15);
	uppercase(strncpy(pass, password, MIN(14, strlen(password))));

	ntlm_set_key(MEM(pass, unsigned char, 0), &context);
	gl_des_ecb_encrypt(&context, magic, keys);

	ntlm_set_key(MEM(pass, unsigned char, 7), &context);
	gl_des_ecb_encrypt(&context, magic, keys+8);

	memset(keys+16, 0, 5);
	ntlm_calc_resp(dst, keys, challenge);

	free(pass);
	free(keys);
}

static void ntlm_nt_password(char *dst, char *password, char *challenge) {
	char *u16, *keys;
	int len;

	keys = new(24);
	len = unicode(&u16, password);
	md4_buffer(u16, len, keys);
	free(u16);

	memset(keys+16, 0, 5);
	ntlm_calc_resp(dst, keys, challenge);

	free(keys);
}

int ntlm_request(char **dst, char *hostname, char *domain, int nt, int lm, uint32_t flags) {
	char *buf, *tmp;
	int dlen, hlen;

	dlen = strlen(domain);
	hlen = strlen(hostname);

	if (debug) {
		printf("NTLM Request:\n");
		printf("\t   Domain: %s\n", domain);
		printf("\t Hostname: %s\n", hostname);
		printf("\t    Flags: 0x%X\n", U32LE(flags ? flags : (nt ? 0xB207 : 0xB206)));
	}

	buf = new(NTLM_BUFSIZE);
	memcpy(buf, "NTLMSSP\0", 8);
	VAL(buf, uint32_t, 8) = U32LE(1);
	VAL(buf, uint32_t, 12) = U32LE(flags ? flags : (nt ? 0xB207 : 0xB206));
	VAL(buf, uint16_t, 16) = U16LE(dlen);
	VAL(buf, uint16_t, 18) = U16LE(dlen);
	VAL(buf, uint32_t, 20) = U32LE(32 + hlen);
	VAL(buf, uint16_t, 24) = U16LE(hlen);
	VAL(buf, uint16_t, 26) = U16LE(hlen);
	VAL(buf, uint32_t, 28) = U32LE(32);

	if (!nt) {
		tmp = uppercase(strdupl(hostname));
		memcpy(buf+32, tmp, hlen);
		free(tmp);

		tmp = uppercase(strdupl(domain));
		memcpy(buf+32+hlen, tmp, dlen);
		free(tmp);
	} else {
		memcpy(buf+32, hostname, hlen);
		memcpy(buf+32+hlen, domain, dlen);
	}

	*dst = buf;
	return 32+dlen+hlen;
}

char *printmem(char *src, size_t len) {
	char hextab[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	char *tmp;
	int i;

	tmp = new(2*len+1);
	for (i = 0; i < len; ++i) {
		tmp[i*2] = hextab[(uint8_t)src[i] >> 4];
		tmp[i*2+1] = hextab[src[i] & 0x0F];
	}

	return tmp;
}

char *printuc(char *src, size_t len) {
	char *tmp;
	int i;

	tmp = new((len+1)/2 + 1);
	for (i = 0; i < len/2; ++i) {
		tmp[i] = src[i*2];
	}

	return tmp;
}

/*
void dump(char *src, size_t len) {
	int i, j;
	char *tmp;

	tmp = new(len*3+4);
	for (i = 0; i < len; ++i) {
		snprintf(tmp+i*3, 4, "%0hhX   ", src[i]);
		printf("%c ", src[i]);
	}
	printf("\n%s\n", tmp);
	free(tmp);
}
*/

int ntlm_response(char **dst, char *challenge, char *username, char *password, char *hostname, char *domain, int nt, int lm) {
	char pwlm[24], pwnt[24];
	char *buf, *udomain, *uuser, *uhost, *tmp;
	int dlen, ulen, hlen, lmlen = 0, ntlen = 0;
	uint32_t flags;
	uint16_t tpos, ttype, tlen;

	if (lm) {
		lmlen = 24;
		ntlm_lm_password((char *)pwlm, password, MEM(challenge, char, lmlen));
	}

	if (nt) {
		ntlen = 24;
		ntlm_nt_password((char *)pwnt, password, MEM(challenge, char, ntlen));
	}

	if (nt) {
		dlen = unicode(&udomain, domain);
		ulen = unicode(&uuser, username);
		hlen = unicode(&uhost, hostname);
	} else {
		udomain = uppercase(strdupl(domain));
		uuser = uppercase(strdupl(username));
		uhost = uppercase(strdupl(hostname));

		dlen = strlen(domain);
		ulen = strlen(username);
		hlen = strlen(hostname);
	}

	if (debug) {
		printf("NTLM Challenge:\n");
		tmp = printmem(MEM(challenge, char, lmlen), 8);
		printf("\tChallenge: %s\n", tmp);
		free(tmp);
		flags = U32LE(VAL(challenge, uint32_t, 20));
		printf("\t    Flags: 0x%X\n", flags);

		tpos = U16LE(VAL(challenge, uint16_t, 44));
		while ((ttype = U16LE(VAL(challenge, uint16_t, tpos)))) {
			tlen = U16LE(VAL(challenge, uint16_t, tpos+2));

			if (ttype == 0x1)
				printf("\t   Server: ");
			else if (ttype == 0x2)
				printf("\tNT domain: ");
			else if (ttype == 0x3)
				printf("\t     FQDN: ");
			else if (ttype == 0x4)
				printf("\t   Domain: ");
			else if (ttype == 0x5)
				printf("\t      TLD: ");
			else
				printf("\t  Unknown: ");

			tmp = printuc(MEM(challenge, char, tpos+4), tlen);
			printf("%s\n", tmp);
			free(tmp);

			tpos += 4+tlen;
		}

		printf("NTLM Response:\n");
		printf("\t Hostname: '%s'\n", hostname);
		printf("\t   Domain: '%s'\n", domain);
		printf("\t Username: '%s'\n", username);
		printf("\t Password: '%s'\n", password);
		if (nt) {
			tmp = printmem(pwnt, 24);
			printf("\t  NT hash: %s\n", tmp);
			free(tmp);
		}
		if (lm) {
			tmp = printmem(pwlm, 24);
			printf("\t  LM hash: %s\n", tmp);
			free(tmp);
		}
	}

	buf = new(NTLM_BUFSIZE);
	memcpy(buf, "NTLMSSP\0", 8);
	VAL(buf, uint32_t, 8) = U32LE(3);

	/* LM */
	VAL(buf, uint16_t, 12) = U16LE(lmlen);
	VAL(buf, uint16_t, 14) = U16LE(lmlen);
	VAL(buf, uint32_t, 16) = U32LE(64+dlen+ulen+hlen);

	/* NT */
	VAL(buf, uint16_t, 20) = U16LE(ntlen);
	VAL(buf, uint16_t, 22) = U16LE(ntlen);
	VAL(buf, uint32_t, 24) = U32LE(64+dlen+ulen+hlen+lmlen);

	/* Domain */
	VAL(buf, uint16_t, 28) = U16LE(dlen);
	VAL(buf, uint16_t, 30) = U16LE(dlen);
	VAL(buf, uint32_t, 32) = U32LE(64);

	/* Username */
	VAL(buf, uint16_t, 36) = U16LE(ulen);
	VAL(buf, uint16_t, 38) = U16LE(ulen);
	VAL(buf, uint32_t, 40) = U32LE(64+dlen);

	/* Hostname */
	VAL(buf, uint16_t, 44) = U16LE(hlen);
	VAL(buf, uint16_t, 46) = U16LE(hlen);
	VAL(buf, uint32_t, 48) = U32LE(64+dlen+ulen);

	/* Session */
	VAL(buf, uint16_t, 52) = U16LE(0);
	VAL(buf, uint16_t, 54) = U16LE(0);
	VAL(buf, uint16_t, 56) = U16LE(64+dlen+ulen+hlen+lmlen+ntlen);

	/* Flags */
	VAL(buf, uint32_t, 60) = U32LE(VAL(challenge, uint32_t, 20));

	memcpy(MEM(buf, char, 64), udomain, dlen);
	memcpy(MEM(buf, char, 64+dlen), uuser, ulen);
	memcpy(MEM(buf, char, 64+dlen+ulen), uhost, hlen);
	memcpy(MEM(buf, char, 64+dlen+ulen+hlen), pwlm, lmlen);
	memcpy(MEM(buf, char, 64+dlen+ulen+hlen+24), pwnt, ntlen);

	free(uhost);
	free(uuser);
	free(udomain);

	*dst = buf;
	return 64+dlen+ulen+hlen+lmlen+ntlen;
}
