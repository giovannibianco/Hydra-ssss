/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://public.eu-egee.org/partners/ for details on 
 * the copyright holders.
 * For license conditions see the license file or
 * http://eu-egee.org/license.html
 *
 * Testprogram for Shamir secret sharing scheme 
 * (joining for given split keys (NULL for not known keys))
 *
 * Usage:  ./joinKey keyLength splitKey1 splitKey2 .... splitKeyN
 *
 * Authors: 
 *      Trygve Aspelien <trygve.aspelien@bccs.uib.no>
 *
 * $Id: joinKey.c,v 1.2 2006-08-04 15:22:05 szamsu Exp $
 */

#include <glite/security/ssss.h>

// =============================     MAIN    ================================================
/**  Testprogram for Shamir secret sharing scheme   */
int main(int argc, char** argv){
  int keyLength=0;
  int nShares=0;
  int i,j;
  unsigned char *jKey;
  unsigned char ** keys;

  if(argc < 3){
    printf("Usage: progname keyLength splitKey1 splitKey2 .... splitKeyN");
    printf("\nExamples: ");
    printf("\nTo recover key: 64aa67e55e5a52ac704b58bb0e1c2695");
    printf("\nKey with size 32 chars, need two keys to recover secret and I may have e.g. keys 3 and 4.");
    printf("\n./joinKey 32 NULL NULL c9952de5f904a1939c223e6bc866dd7e 40986fe02ca1bbe0aabf8af65bdec526");
    printf("\nRecover a custom key 12345678 with size 8 chars. Need 3 split keys to recover the key and have split keys 1,2 and 5..");
    printf("\n./joinKey 8 NULL 6fbc0334 d2ecd103 NULL NULL ce4a189d");
  }
  else{
    nShares=argc-2;
    keyLength=atoi(&argv[1][0]);
    // Overriding:
    verbose=0;

    // Allocate splitkeys
    keys = (unsigned char **) malloc(nShares*sizeof(char *));
    for(i=0;i<nShares;i++){
      keys[i]=(unsigned char *)malloc(keyLength*sizeof(char));
    } 

    for(i=0;i<nShares;i++){
      if(argv[i+2][0]=='N' && argv[i+2][1]=='U' && argv[i+2][2]=='L' && argv[i+2][3]=='L'){
	keys[i]=NULL;
      }else{
	keys[i]=&argv[i+2][0];
	for(j=0;j<keyLength;j++){
	  if(keys[i][j]==' ') keys[i][j]='0';
	}
      }
    }
      
    // Join keys
    jKey=(unsigned char *)joinKeySSS(keys,nShares);
    printf("\nJoined key : %s\n",jKey);
  }
  return 0;
}
