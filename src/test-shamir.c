/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://public.eu-egee.org/partners/ for details on 
 * the copyright holders.
 * For license conditions see the license file or
 * http://eu-egee.org/license.html
 *
 * Testprogram for Shamir secret sharing scheme 
 *      (splitting and joining for all shares)
 * Usage: ./test-shamir nShares nNeeded key
 *
 * Authors: 
 *      Trygve Aspelien <trygve.aspelien@bccs.uib.no>
 *
 * $Id: test-shamir.c,v 1.4 2006-08-15 14:22:51 szamsu Exp $
 */

#include <glite/security/ssss.h>
#include "stdlib.h"

// =============================     MAIN    ================================================
/**  Testprogram for Shamir secret sharing scheme   */
int main(int argc, char** argv){
  int nNeeded=0;
  int nShares=0;
  int i;
  unsigned char *key;
  unsigned char *jKey;
  unsigned char ** keys;

  if(argc < 3){
    printf("Usage: progname nShares nNeeded key");
    printf("\nExamples: ");
    printf("\n5 split keys 2 are needed to unlock");
    printf("\n./test-shamir 5 2 123456781234678");
    printf("\n7 split keys, 3 are needed to unlock.");
    printf("\n./test-shamir 7 3 12345678");
    printf("\n");
    exit(EXIT_FAILURE);
  }

  nShares=atoi(argv[1]);
  nNeeded=atoi(argv[2]);
  key = argv[3];

  printf("\nKey to split : %s",key);

  // Split keys
  keys = glite_security_ssss_split_key(key, nShares, nNeeded);

  printf("\n\nSplit keys:");
  for(i=0;i<nShares;i++){
    printf("\nx = %i splitKey = %s",i+1,keys[i]);
  }

  // Join keys
  jKey = glite_security_ssss_join_keys(keys, nShares);
  printf("\n\nJoined key : %s\n",jKey);

  i = strcmp(key, jKey);
  if (0 == i) {
    printf("The joined key is the same as the original.\n");
  }
  else {
    printf("ERROR: the original and the joined key are not the same!\n");
  }
  return i;
}

/* vim:set sw=2 ts=2 et si: */
