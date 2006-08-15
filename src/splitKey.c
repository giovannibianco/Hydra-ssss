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
 * $Id: splitKey.c,v 1.5 2006-08-15 15:51:10 szamsu Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glite/security/ssss.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PROGNAME "glite-ssss-split-key"

static void print_usage_and_die (int exit_code) {
  printf("\n");
  printf("<%s> Version %s by (C) EGEE\n", PROGNAME, PACKAGE_VERSION);
  printf("usage: %s [-q] [-h] <nShares> <nNeeded> <key>\n", PROGNAME);
  printf("Examples: ");
  printf("5 split keys 2 are needed to unlock\n");
  printf("./%s 5 2 1234567812345678\n", PROGNAME);
  printf("7 split keys, 3 are needed to unlock.\n");
  printf("./%s 7 3 12345678\n", PROGNAME);
  exit(exit_code); 
}

int main(int argc, char** argv){
  unsigned int nNeeded;
  unsigned int nShares;
  unsigned int i;
  int flag;
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

  nShares = (unsigned int) atoi(argv[optind + 0]);
  nNeeded = (unsigned int) atoi(argv[optind + 1]);
  key = argv[optind + 2];
  
  if (verbose) printf("\nKey to split (%d of %d): %s", nNeeded, nShares, key);

  // Split keys 
  keys = glite_security_ssss_split_key(key,nShares,nNeeded);
  if(keys==NULL){
    printf("\n\nError in splitting key. Check logfile");
    return 1;
  }

  if (verbose) printf("\n\nSplit keys:");
  for(i=0;i<nShares;i++){
    if (verbose) printf("\n%i. splitKey = ",i+1);
    printf("%s ", keys[i]);
  }
  printf("\n");

  return 0;
}

// vim:set ts=2 sw=2 et:
