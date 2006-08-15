/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://public.eu-egee.org/partners/ for details on 
 * the copyright holders.
 * For license conditions see the license file or
 * http://eu-egee.org/license.html
 *
 * Testprogram for Shamir secret sharing scheme (splitting for all shares)
 * Usage:  ./splitKey nShares nNeeded key
 *
 * Authors: 
 *      Trygve Aspelien <trygve.aspelien@bccs.uib.no>
 *
 * $Id: splitKey.c,v 1.3 2006-08-15 14:22:51 szamsu Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glite/security/ssss.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PROGNAME "glite-ssss-split-key"

void print_usage_and_die (int exit_code) {
  printf("\n");
  printf("<%s> Version %s by (C) EGEE\n", PROGNAME, PACKAGE_VERSION);
  printf("usage: %s [-q] [-h] <nShares> <nNeeded> <key>\n", PROGNAME);
  printf("\nExamples: ");
  printf("\n5 split keys 2 are needed to unlock");
  printf("\n./splitKey 5 2 1234567812345678");
  printf("\n7 split keys, 3 are needed to unlock.");
  printf("\n./splitKey 7 3 12345678");
  printf("\n");
  exit(exit_code); 
}

int main(int argc, char** argv){
  int nNeeded;
  int nShares;
  int i, flag;
  int verbose = 1;    
  unsigned char *key;
  unsigned char ** keys;

  while ((flag = getopt (argc, argv, "hq")) != -1) {
    switch (flag) {
      case 'h':
        print_usage_and_die(EXIT_SUCCESS);
        break;
      case 'q':
        verbose = 0;
        break;
      default:
        print_usage_and_die(EXIT_FAILURE);
        break;
    }
  }

  if(argc != (optind + 3)){
    print_usage_and_die(EXIT_FAILURE);
  }

  nShares = atoi(argv[optind + 0]);
  nNeeded = atoi(argv[optind + 1]);
  key = argv[optind + 2];
  
  if (verbose) printf("\nKey to split (%d of %d): %s", nNeeded, nShares, key);

  // Split keys 
  keys = glite_security_ssss_split_key(key,nShares,nNeeded);
  
  if (verbose) printf("\n\nSplit keys:");
  for(i=0;i<nShares;i++){
    if (verbose) printf("\n%i. splitKey = ",i+1);
    printf("%s ", keys[i]);
  }
  printf("\n");

  return 0;
}

// vim:set ts=2 sw=2 et:
