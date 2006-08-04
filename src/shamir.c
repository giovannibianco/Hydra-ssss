/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://public.eu-egee.org/partners/ for details on 
 * the copyright holders.
 * For license conditions see the license file or
 * http://eu-egee.org/license.html
 *
 * Authors: 
 *      Trygve Aspelien <trygve.aspelien@bccs.uib.no>
 *
 * $Id: shamir.c,v 1.1.1.1 2006-08-04 14:56:01 szamsu Exp $
 */

#include <glite/security/ssss.h>

// Functions and test for the Shamir Secret Sharing Scheme

// Routine for calculation of modular inverse 
long inverseModulo(long n){
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
    printf("\nNot able to modulo innverse %li",n);
    printf("\nValues: %li %li %li %li",b[0],b[1],n,prime);
    exit(EXIT_FAILURE);
  }
  long inverse = b[1];
  
  while (inverse < 0)
    inverse += prime;
  
  return inverse;
}

// Error handling
void handleError(char *thisFile, int thisLine,char *err)
{
  if(err!=NULL) {
    printf("\n\n*****************************************");
    printf("\n  ERROR: %s",err);
    printf("\n*****************************************");
  
  } else{
    printf("\n\n*****************************************");
    printf("\n  ERROR: No error message was provided for the error");
    printf("\n*****************************************");
  }
  printf("\n\nError occured in file %s on line: %i",thisFile,thisLine);
  exit(EXIT_FAILURE);
}

// ======= Tests performed by the scheme =============0
// Testing the length of the string
void lengthTest(int keyLength){
  char *str;
  char s1[80];
  if (keyLength < 4) {
    sprintf(s1,"keyLength (%i) < 4",keyLength);
    str=(char *)&s1;
    handleError(__FILE__, __LINE__,str);
  }
  if (keyLength%4!=0) {
    sprintf(s1,"keyLength (%i) must be dividable by 4",keyLength);
    str=(char *)&s1;
    handleError(__FILE__, __LINE__,str);
  }
}

// Testing for valid hex chars
void hextest(char x){
  int asci;
  char *str;
  char s1[80];

  asci=(int) x;
  //printf("\n%i",(int) x);
  if (asci < 48 || asci > 102 ) {
    sprintf(s1,"Invalid hex value :  %c ",asci);
    str=(char *)&s1;
    handleError(__FILE__, __LINE__,str);
  } else{
    if (asci > 57 &&  asci < 97 ) {
      if(asci < 65 || asci > 70) {
	sprintf(s1,"Invalid hex value :  %c ",asci);
	str=(char *)&s1;
	handleError(__FILE__, __LINE__,str);
      }
    }
  }
}

// Generate a random hex key in chunks of 4 chars
unsigned char * generateKey(int len){
  unsigned char *keyf;
  unsigned char bit[5];
  int i,ii,nBytes,iByte;

  lengthTest(len);
  nBytes=len/4;
  short string[nBytes];

  keyf=malloc(sizeof(char)*len);

  if (! RAND_bytes((unsigned char *)&string[0],sizeof(short)*nBytes))
    handleError(__FILE__, __LINE__,"Error creating key");

  for(iByte=0;iByte<nBytes;iByte++){
    for(i=0;i<4;i++) bit[i]='0';
    bit[4]='\0';
    sprintf(bit,"%4x",abs(string[iByte]));
    for(i=0;i<4;i++){
      ii=(iByte*4)+i;
      *(keyf+ii)=bit[i];
      if(bit[i]==' ') {
	*(keyf+(iByte*4)+i)='0';
      }
    }
    printf(" ");
  }
  *(keyf+(len))='\0';
  
  return keyf;
}
