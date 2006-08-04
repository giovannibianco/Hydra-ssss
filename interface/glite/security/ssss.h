/** \file ssss.h
 *
 * Definition header file for shamir.c (SSS)
 *
 * Definition for Shamir secret sharing (SSS) scheme.
 *
 * Based on "How to Share a Secret", by Adi Shamir, Communications of
 * the ACM, November, 1979, Volume 22, Number 11, page 612.
 *
 * SSS provides a perfect \f$(t,n)\f$-threshold secret sharing scheme.
 * i.e. it is a method for \f$n\f$ parties to carry shares \f$s_i\f$ of
 * a secret s such that any \f$t\f$ of them are needed to recover
 * the secret, but so that no \f$t-1\f$ of them can do so. The threshold
 * is perfect if knowledge of \f$t-1\f$ or fewer shares provides no information
 * regarding \f$s\f$.
 * Shamir \f$(t,n)\f$-threshold scheme is based on classical Lagrange polynomial
 * interpolation of degree \f$t-1\f$ with modular arithmetic instead of real ari
thmetic.
 * The set of integers modulo a prime number 'prime' forms a field in which
 * interpolation is possible.
 * We choose to break the key in substrings of 4 characters handled separately 
 * (hex value of 0 - 2^16). 
 * It is also assumed that the hex key is based on positive numbers.
 * The prime number has to be bigger than the largest number than can
 * be represented (i.e. 0xff) and the number of shares n.
 * In order to handle all byte values (0x00-0xff) and so that we can multiply
 * two such numbers, the shared secrets will fit in a 16-bits integer
 * (unsigned short). The prime has to be less than \f$2^16\f$ in order to fit them
 * all. The largest such prime is 65521.
 *
 * \example test-shamir.c
 * \example splitKey.c
 * \example joinKey.c
 * These are simple split/join tests for Shamir secret sharing scheme.
 *
 * The scheme needs the header file cryptc.h to be included. 
 */

#ifndef SSSS_H
#define SSSS_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

int verbose;
// Setting highest possible prime less than 2^16
static const long prime = 65521;

unsigned char ** splitKeySSS(unsigned char * key,int nShares,int nNeeded);
unsigned char * joinKeySSS(unsigned char **keysf,int nShares);

unsigned char * generateKey(int len);
long inverseModulo(long n);
void handleError(char *thisFile,int thisLine,char* err);
void lengthTest(int keyLength);
void hextest(char x);



#endif // SSSS_H
