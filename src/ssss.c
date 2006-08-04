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
 * $Id: ssss.c,v 1.1.1.1 2006-08-04 14:56:01 szamsu Exp $
 */

#include <glite/security/ssss.h>

/*
 *                  ======================
 *                   SHAMIR SCHEME STARTS
 *                  ======================
*/

// =============== SPLITKEY ===================================================================
// Routine allocates the char** with split keys to be returned. Deallocation has to be done 
// later by the user of the routine. 
unsigned char ** splitKeySSS(unsigned char * keyf,int nShares,int nNeeded){
  int i,j,nBytes,iByte;
  unsigned char **keysf;
  int keyLength = strlen(keyf);
  unsigned char bit[5];
  char *str;
  char s1[80];

  // Test if nShares provided
  if (nShares <= 0) {
    sprintf(s1,"nShares (%i) must be greater than 0",nShares);
    str=(char *)&s1;
    handleError(__FILE__, __LINE__,str);
  }  

  // Test if nNeeded provided
  if (nNeeded <= 0) {
    sprintf(s1,"nNeeded (%i) must be greater than 0",nNeeded);
    str=(char *)&s1;
    handleError(__FILE__, __LINE__,str);
  }

  // If not enough shares => EXIT
  if (nShares < nNeeded) {
    sprintf(s1,"nShares (%i) < nNeeded (%i)",nShares,nNeeded);
    str=(char *)&s1;
    handleError(__FILE__, __LINE__,str);
  }
  // Test keylength
  lengthTest(keyLength);

  // Test hex value for valid chars
  for(i=0;i<keyLength;i++)
    hextest(keyf[i]);

  // Everything OK, continues.....

  // Setting loop variable
  nBytes= (int) keyLength/4;

  // Allocate splitkeys
  keysf = (unsigned char **) malloc(nShares*sizeof(char *));
  for(i=0;i<nShares;i++){
    keysf[i]=(unsigned char *)malloc(keyLength*sizeof(char));
  } 
  // Initialize splitKeys
  for(i=0;i<nShares;i++){
    for(j=0;j<keyLength;j++){
      keysf[i][j]='0';
    }
    keysf[i][keyLength]='\0';
  }

  // Creating polynom (up to 2^16 = short)
  unsigned short polynom[nNeeded];

  // Loop over 4 bit's
  for(iByte=1;iByte<=nBytes;iByte++){

    // Initialize polynom
    for(i=0;i<nNeeded;i++) polynom[i]=0;

    // Randomizing polynom
    if (! RAND_bytes((unsigned char *)&polynom[0],sizeof(polynom)))
      handleError(__FILE__, __LINE__,"Error creating polynom");
    
    // Have to insert the secret for x=0, must convert hex string to short
    // Pointer to end of string
    for(i=0;i<4;i++) bit[i]='0';
    bit[4]='\0';
    for(i=0;i<4;i++){
      bit[i]=*(keyf+i+((iByte-1)*4));
    }
    bit[4]='\0';

    // Conversion of hex keystring to integer
    unsigned short s_key = strtol(bit,NULL,16);

    // Setting key as polynom for x=0
    polynom[nNeeded-1]=s_key;
    
    if(verbose!=0){
      printf("\nRandom polynom:\n");    
      for(i=0;i<nNeeded;i++)
	printf("%i (x^%i) ",polynom[i],nNeeded-1-i);
      printf("\nHex: ");    
      for(i=0;i<nNeeded;i++)
	printf("x^%i=%x ",nNeeded-1-i,polynom[i]);
    }
    
    //--------------------------------------------------
    //Got a random polynom, creating nShares keys.
    //Sorting polynoms from highest to lowest order
    //-------------------------------------------------- 
    
    unsigned long xx; // x counter
    unsigned long xtemp,xtt,xt; // Summation variable
    
    for(xx=1;xx<=nShares;xx++){  
      xtemp=0;
      if(verbose!=0) printf("\nx=%li ",xx );
      for(i=0;i<nNeeded;i++){
	//xt=((unsigned long) pow((xx),(nNeeded-1-i)))%prime;
	xt=1;
	for(j=0;j<(nNeeded-1-i);j++){
	  xt=(unsigned long) (xt*xx)%prime;
	  //printf(" i=%i j=%i xt=%i ",i,j,xt);
	}
	
	while(xt<0) xt+=prime;
	xtt= (unsigned long) (polynom[i]*xt)%prime;
	while(xtt<0) xtt+=prime;
	xtemp = (xtemp+xtt)%prime;
	while(xtemp<0) xtemp+=prime;
	if(verbose!=0) printf("i=%i (%i) => %li & %li ",i,(nNeeded-1-i),xt,xtt);
      }
      if(verbose!=0) printf("y=%li",xtemp);
     
      for(i=0;i<4;i++) bit[i]='0';
      bit[4]='\0';
      sprintf(bit,"%4lx",xtemp);
      
      for(i=0;i<4;i++){
	keysf[xx-1][i+(((iByte-1))*4)]=bit[i];
	if(keysf[xx-1][i+(((iByte-1))*4)]==' ') keysf[xx-1][i+(((iByte-1))*4)]='0';
      }
      // Add terminating 0
      if(iByte==nBytes){
	keysf[xx-1][nBytes*4]='\0';
      }
    }
    
  }
  return keysf;
}

// ============          joinKeySSS   =============================================
unsigned char * joinKeySSS(unsigned char **keysf,int nShares){
  unsigned char * jKey;
  unsigned long x[nShares];
  long i,j,ii,jj,k;
  long num=0;
  long denom=0;
  unsigned long isecret=0; 
  long inarray[nShares];
  unsigned long c[nShares];
  unsigned long ikeys[nShares];
  long  nn,nBytes,iByte;
  unsigned char bit[5];
  long keyLength,start;
  char *str;
  char s1[80];

  // Test if nShares provided
  if (nShares <= 0) {
    sprintf(s1,"nShares (%i) must be greater than 0",nShares);
    str=(char *)&s1;
    handleError(__FILE__, __LINE__,str);
  }  
  // Set keyLength for first well defined string
  start=0;
  for (i=0;keysf[i]==NULL;i++)
    start=i+1;
  keyLength=strlen(keysf[start]);

  // Check length of split-keys
  for (i=start;i<nShares;i++){
    if(keysf[i]!=NULL){
      
      if(keyLength!=strlen(keysf[i])){
	handleError(__FILE__, __LINE__,"All the split keys have to have the same length");
      }    
    }
  }
  
  // Find active x-points
  nn=0;
  for (i=0;i<nShares;i++){
    inarray[i]=0;
    x[i]=0;
    if(keysf[i]!=NULL) {

      inarray[i]=1;
      x[i]=i+1;
      nn++;
    }
  }

  if(verbose!=0) printf("\nJoining key with %li split keys...",nn);

  lengthTest(keyLength);

  // Setting loop variable
  nBytes= (int) keyLength/4;
  jKey=malloc(sizeof(char)*keyLength);
  
  

  for(i=0;i<(nBytes*4);i++) *(jKey+i)='0';
  *(jKey+(nBytes*4))='\0';

  if(verbose!=0){
    for(i=0;i<nShares;i++){
      printf("\nsplitKey  x=%li ",x[i]);
      for(iByte=1;iByte<=nBytes;iByte++){
	
	if(inarray[i]!=0){
	  for(j=0;j<4;j++){
	    bit[j]=keysf[i][j+((iByte-1)*4)];
	  }
	  bit[4]='\0';
	  for(k=0;k<4;k++)
	    printf("%c",bit[k]);
	  printf(" (%li) ",strtol(bit,NULL,16)); 
	}
      }
    }
  }
  
  // Loop over 4 chars
  for(iByte=1;iByte<=nBytes;iByte++){
     
    // Convert hex keys to integers
    for(i=0;i<nShares;i++){
      if(inarray[i]!=0){

	for(j=0;j<4;j++){
	  ii=j+((iByte-1)*4);
	  bit[j]=keysf[i][ii];
	  // Test hex value
	  hextest(bit[j]);
	}
	bit[4]='\0';
	
	ikeys[i]=strtol(bit,NULL,16);
      }else{
	ikeys[i]=0;
      }
    }
    
    // Get key back from split keys
    for (i=0;i<nShares;i++){
      ii=i+1;
      if(inarray[i]!=0){
	denom=1;
	num=1;
	for (j=0;j<nShares;j++){
	  jj=j+1;
	  if(inarray[j]!=0){
	    if(jj!=ii){
	      num*=-jj%prime;
	      denom*=(ii-jj)%prime;
	      num=num%prime;
	      denom=denom%prime;
	    }
	  }
	}
	num=num%prime;
	denom=denom%prime;
	// Start array from 0
	while(num<0) num+=prime;
	while(denom<0) denom+=prime;
	denom=inverseModulo(denom);
	while(denom<0) denom+=prime;
	c[i]= (unsigned long) (num*denom)%prime;
	while(c[i]<0) c[i]+=prime;
	if(verbose!=0) printf("\nc=%li",c[i]);
      }else{
	c[i]=0;
      }
    }
    
    // Defined c and have nNeeded ikeys. Make summation
    unsigned long xt;
    isecret=0;
    for  (i=0;i<nShares;i++){
      if(inarray[i]!=0){
	xt=0;
	xt= (unsigned long) (c[i]*ikeys[i])%prime;
	while(xt<0) xt+=prime;
	isecret= (unsigned long) (isecret+xt)%prime;
	while(isecret<0) isecret+=prime;
	if(verbose!=0) printf("\nc[%li] = %lu x(%li)=%lu ==> %lu %lu %lu %li",i,c[i],i,ikeys[i],(unsigned long) c[i]*ikeys[i],(unsigned long)(c[i]*ikeys[i])/prime,xt,isecret);
      }    
    }
    
    
    isecret=isecret%prime;
    if(verbose!=0) printf("\nIsecret: %li",isecret);
    
    
    for(i=0;i<4;i++) bit[i]='0';
    bit[4]='\0';
    sprintf(bit,"%4lx",isecret);
    for(i=0;i<4;i++){
      if(bit[i]==' ') bit[i]='0';
    }
    for(i=0;i<4;i++) *(jKey+i+((iByte-1)*4))=bit[i];
  }
  *(jKey+(nBytes*4))='\0';

  if(verbose!=0){
    printf("\nJoined Key bits= ");
    for(iByte=1;iByte<=nBytes;iByte++){
      for(i=0;i<4;i++){
	bit[i]=*(jKey+i+((iByte-1)*4));
      }
      bit[4]='\0';
      for(j=0;j<4;j++)
	printf("%c",bit[j]);
      printf(" (%li) ",strtol(bit,NULL,16));
    }
  }
 
  return jKey;
}

