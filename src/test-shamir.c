/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://public.eu-egee.org/partners/ for details on 
 * the copyright holders.
 * For license conditions see the license file or
 * http://eu-egee.org/license.html
 *
 * Testprogram for Shamir secret sharing scheme 
 *      (splitting and joining for all shares)
 * Usage: ./test-shamir keyLength nShares nNeeded [verbose] [key]
 *
 * Authors: 
 *      Trygve Aspelien <trygve.aspelien@bccs.uib.no>
 *
 * $Id: test-shamir.c,v 1.2 2006-08-04 15:22:05 szamsu Exp $
 */

#include <glite/security/ssss.h>

// =============================     MAIN    ================================================
/**  Testprogram for Shamir secret sharing scheme   */
int main(int argc, char** argv){
  int keyLength=0;
  int nNeeded=0;
  int nShares=0;
  int i;
  unsigned char *key;
  unsigned char *jKey;
  unsigned char ** keys;

  if(argc < 4 || argc > 6){
    printf("Usage: progname keyLength nShares nNeeded [verbose] [key]");
    printf("\nExamples: ");
    printf("\nNo verbose and random generated key with size 32 chars. 5 split keys 2 are needed to unlock");
    printf("\n./test-shamir 32 5 2");
    printf("\nNo verbose and custom key 12345678 with size 8 chars. 7 split keys, 3 are needed to unlock.");
    printf("\n./test-shamir 8 7 3 0 12345678");
    printf("\n");
  }
  else{
    verbose=0;
    keyLength=atoi(&argv[1][0]);

    // Allocate key
    key=malloc(sizeof(char)*keyLength);
    for(i=0;i<keyLength;i++) key[i]='0';
    key[keyLength]='\0';
    key=(unsigned char *) generateKey(keyLength);

    nShares=atoi(&argv[2][0]);
    nNeeded=atoi(&argv[3][0]);
    if (argc > 4) verbose=atoi(&argv[4][0]);
    if (argc > 5) key=(unsigned char *) &argv[5][0];

    printf("\nKey to split : %s",key);

    // Split keys
    keys= (unsigned char **) splitKeySSS(key,nShares,nNeeded);

    printf("\n\nSplit keys:");
    for(i=0;i<nShares;i++){
      printf("\nx = %i splitKey = %s",i+1,keys[i]);
    }

    // Join keys
    jKey=(unsigned char *) joinKeySSS(keys,nShares);
    printf("\n\nJoined key : %s\n",jKey);
  }
  return 0;
}
