/*
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://public.eu-egee.org/partners/ for details on 
 * the copyright holders.
 * For license conditions see the license file or
 * http://eu-egee.org/license.html
 *
 * Testprogram for Shamir secret sharing scheme 
 * (joining for given split password parts (NULL for not known keys))
 *
 * Authors: 
 *      Trygve Aspelien <trygve.aspelien@bccs.uib.no>
 *
 * $Id: joinPasswd.c,v 1.2 2006-08-17 11:04:44 taspelie Exp $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glite/security/ssss.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define PROGNAME "glite-ssss-join-passwd"

static void print_usage_and_die (int exit_code) {
    printf("\n");
    printf("<%s> Version %s by (C) EGEE\n", PROGNAME, PACKAGE_VERSION);
    printf("usage: %s [-q] [-h] (join-key|NULL)...\n", PROGNAME);
    printf("Examples:\n");
    printf("To recover password: #%&lkXYt\n");
    printf("Need two parts of the split password but have 5.\n");
    printf("%s 8190b6ea2758da88d522 03274abe284449c750df 84afde832930b8f7cc8d 064672572a1c2836484a 87ce062b2b089766c3f8\n", PROGNAME);
    printf("Need two parts to recover the password and have split part 2 and 4\n");
    printf("%s NULL 03274abe284449c750df NULL 064672572a1c2836484a\n", PROGNAME);
  exit(exit_code); 
}

int main(int argc, char** argv){
  unsigned int nShares=0;
  int flag;
  unsigned int i;
  int verbose = 1;    
  unsigned char *jKey;
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

  if(argc < (optind + 2)){
    print_usage_and_die(EXIT_FAILURE);
  }
 
  nShares = (unsigned int) argc - optind;

  // Allocate splitkeys
  keys = (unsigned char **) malloc(nShares*sizeof(unsigned char *));

  for (i=0; i<nShares; i++) {
    if(strcmp(argv[i + optind], "NULL") == 0) {
      keys[i] = NULL;
    }
    else {
      keys[i] = argv[i + optind];
    }
  }
      
  // Join keys
  jKey = glite_security_ssss_join_passwd(keys, nShares);
  if(jKey==NULL){
    printf("\n\nError in joining pasword. Check logfile");
    return 2;
  }
  if (verbose) printf("\nJoined password : ");
  printf("%s\n",jKey);

  return 0;
}

// vim:set ts=2 sw=2 et:
