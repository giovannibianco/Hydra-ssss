/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://public.eu-egee.org/partners/ for details on 
 * the copyright holders.
 * For license conditions see the license file or
 * http://eu-egee.org/license.html
 *
 * Functions and tests for the SSSS
 *
 * Authors: 
 *      Trygve Aspelien <trygve.aspelien@bccs.uib.no>
 *
 * $Id: shamir-funcs.c,v 1.2 2006-08-15 14:22:51 szamsu Exp $
 */

#include "ssssI.h"

// Functions and test for the Shamir Secret Sharing Scheme

/** Routine for calculation of modular inverse */
int inverseModulo(long n, long *in){
  // Assume that we want to compute n(-1)(mod prime) (with gcd(prime,n)=1.
  // Run the Extended Euclidean algorithm to get a and b such that a*prime+b*n=1.
  // Rearranging this result, we see that a*prime=1-b*n, or b*n=1(mod prime).
  // This solves the problem of finding the modular inverse of n, as this shows
  // that n(-1)=b(mod prime).
  
  // More information about Basics of Computational Number Theory
  // can be found (at the date of Nov. 11, 2005)
  // http://www.math.oumbc.edu/~campbell/NumbThy/Class/BasicNumbThy.html
  
  int i;
  long a[3] = { 1L, 0L, prime };
  long b[3] = { 0L, 1L, n };
  
  while (a[2] != 0) {
    if (a[2] < b[2])
      for (i=0; i<3; ++i) {
        long tmp = a[i];
        a[i] = b[i];
        b[i] = tmp;
      }
    long q = a[2] / b[2];
    for (i=0; i<3; ++i)
      a[i] -= q*b[i];
  }

  // TEST FOR CORRECT RESULT
  // a*prime+b*n=1 where a is in b[0] and b is in b[1]
  if ((b[0]*prime+b[1]*n)%prime != 1) {
    SSSS_I_log4c_ERROR("Not able to modulo innverse %li",n);
    SSSS_I_log4c_ERROR("Values: %li %li %li %li",b[0],b[1],n,prime);
    return 0;
  }
  long inverse = b[1];
  
  while (inverse < 0)
    inverse += prime;
  
  *in = inverse;
  return 1;
}

// ======= Tests performed by the scheme =============0
/** Testing the length of the string*/
int lengthTest(int keyLength){
  if (keyLength < 4) {
    SSSS_I_log4c_ERROR("keyLength (%i) < 4",keyLength);
    return 0;
  }
  if (keyLength%4!=0) {
    SSSS_I_log4c_ERROR("keyLength (%i) must be dividable by 4",keyLength);
    return 0;
  }

  return 1;
}

/** Testing for valid hex chars*/
int hextest(char x){
  int asci;

  asci=(int) x;
  //SSSS_I_log4c_DEBUG("%i",(int) x);
  if (asci < 48 || asci > 102 ) {
    SSSS_I_log4c_ERROR("Invalid hex value :  %c ",asci);
    return 0;
  } else{
    if (asci > 57 &&  asci < 97 ) {
      if(asci < 65 || asci > 70) {
        SSSS_I_log4c_ERROR("Invalid hex value :  %c ",asci);
        return 0;
      }
    }
  }

  return 1;
}

// vim:set ts=2 sw=2 et:
