/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://public.eu-egee.org/partners/ for details on 
 * the copyright holders.
 * For license conditions see the license file or
 * http://eu-egee.org/license.html
 *
 * Testprogram for Shamir secret sharing scheme 
 *      (splitting and joining for all shares)
 *
 * Authors: 
 *      Trygve Aspelien <trygve.aspelien@bccs.uib.no>
 *
 * $Id: test-shamir-ascii.c,v 1.2 2006-08-17 11:05:11 taspelie Exp $
 */

#include <glite/security/ssss.h>
#include "stdlib.h"
#include "stdio.h"
#include "string.h"

#define PROGNAME "test-shamir-ascii"

// =============================     MAIN    ================================================
/**  Testprogram for Shamir secret sharing scheme   */
int main(int argc, char** argv){
  unsigned int nNeeded=0;
  unsigned int nShares=0;
  unsigned int i;
  unsigned char *key;
  unsigned char *jKey;
  unsigned char ** keys;

  if(argc < 3){
    printf("Usage: progname nShares nNeeded key\n");
    printf("Examples: (NOTE: \" marks are needed if shell variables are included in the password string)\n");
    printf("5 split passwords 2 are needed to unlock\n");
    printf("%s 5 2 \"#%&lkXYt\"\n",PROGNAME);
    printf("7 split keys, 3 are needed to unlock.\n");
    printf("%s 7 3 \"#%&lkXYt\"\n",PROGNAME);
    exit(EXIT_FAILURE);
  }

  nShares= (unsigned int) atoi(argv[1]);
  nNeeded= (unsigned int) atoi(argv[2]);
  key = argv[3];

  printf("\nPassword to split (%d of %d): %s", nNeeded, nShares, key);
  
  // Split keys
  keys = glite_security_ssss_split_passwd(key, nShares, nNeeded);
  if(keys==NULL){
    printf("\n\nError in splitting password. Check logfile");
    return 1;
  }

  printf("\n\nSplit passwords:");
  for(i=0;i<nShares;i++){
    printf("\nx = %i splitKey = %s",i+1,keys[i]);
  }
  
  // Join passwords
  jKey = glite_security_ssss_join_passwd(keys, nShares);
  if(jKey==NULL){
    printf("\n\nError in joining password. Check logfile");
    return 2;
  }

  printf("\n\nJoined password : %s\n",jKey);

  i = strcmp(key, jKey);
  if (0 == i) {
    printf("The joined password is the same as the original.\n");
  }
  else {
    printf("ERROR: the original and the joined passwords are not the same!\n");
  }
  return i;
  
}

/* vim:set sw=2 ts=2 et si: */
