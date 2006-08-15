/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://public.eu-egee.org/partners/ for details on 
 * the copyright holders.
 * For license conditions see the license file or
 * http://eu-egee.org/license.html
 *
 * Testprogram for Shamir secret sharing scheme: key generation
 * Usage:  ./genKey keyLength
 *
 * Authors: 
 *      Trygve Aspelien <trygve.aspelien@bccs.uib.no>
 *      Akos Frohner <Akos.Frohner@cern.ch>
 *
 * $Id: genKey.c,v 1.2 2006-08-15 14:22:51 szamsu Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ssssI.h"

#define PROGNAME "glite-ssss-generate-key"

/** Generate a random hex key in chunks of 4 chars*/
unsigned char * generateKey(int len){
  unsigned char *keyf;
  unsigned char bit[5];
  int i,ii,nBytes,iByte;

  lengthTest(len);
  nBytes=len/4;
  short string[nBytes];

  keyf=malloc(sizeof(char)*len);

  if (! RAND_bytes((unsigned char *)&string[0],sizeof(short)*nBytes)) {
    printf("Error during generating the key!\n");
    exit(EXIT_FAILURE);
  }

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
  }
  *(keyf+(len))='\0';

  return keyf;
}

int main(int argc, char** argv){
  int keyLength;

  if (argc < 2) {
    printf("\n");
    printf("<%s> Version %s by (C) EGEE\n", PROGNAME, PACKAGE_VERSION);
    printf("usage: %s <key-length>\n", PROGNAME);
    exit(EXIT_FAILURE);
  }

  keyLength = atoi(argv[1]);

  printf("%s\n", generateKey(keyLength));

  return 0;
}

// vim:set ts=2 sw=2 et:
