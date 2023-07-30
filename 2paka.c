/* Contributed by Dmitry Kosolapov
 *
 * I haven't tested this much, and I'm personally not familiar with
 * this particular cryptosystem. -Ben Lynn
 */
/* Here we represent the original Yuan-Li ID-Based Authenticated Key Agreement Protocol, 2005.
 * This protocol has 2 stages: Setup and Extract. We represent them inside one code block with demo and time outputs.
 */

/*Yuan-Li protocol description according to:
Quan Yuan and Songping Li, A New Efficient ID-Based Authenticated Key Agreement Protocol, Cryptology ePrint Archive, Report 2005/309

SETUP:
KGS chooses G1, G2, e: G1*G1 -> G2, P, H: {0, 1}* -> G1, s, H - some function for key calculation.
KGS calculates P0 = s*P, publishes {G1, G2, e, P, P0, H1, H} and saves s as master key.

EXTRACT:

For the user with ID public key can be calculated with Qi = H1(ID). KGS generates bound public key Sid = s*Qi.
1. A chooses random a from Z_p*, calculates Sai1 = a*P.
   A -> B: Sai1
2. B chooses random b from Z_p*, calculates Sai2 = b*P.
   B -> A: Sai2
3. A calculates h = a*Sai2 = a*b*P and shared secret key Kab = e(a*P0 + Sa, Sai2 + Q2)
4. B calculates h = b*Sai1 = a*b*P and shared secret key Kba = e(Sai1 + Q1, b*P0 + Sb)
Session key is K = H(A, B, h, Kab).
H was not defined in the original article.
I've defined it as H(A, B, h, Kab)=e(h,H1(A)+H1(B))+Kab.

\u03A8 = Psi symbol
\u03C3 = Sigma symbol
*/

#include <pbc/pbc.h>
#include <pbc/pbc_test.h>

#include <string.h>

int main(int argc, char **argv) {
  pairing_t pairing;
  double t0, t1;
  element_t s, r1, r2, P, P0, Q1, Q2, Pr1, Pr2, sig1, sig2, Sai1, Sai2, Kab, Kba, K, temp1,
    temp2, temp3, temp4, temp5, tmp1, tmp2, tmp3, tmp4, lhs, rhs, X;
  element_t hash1, hash2;

  pbc_demo_pairing_init(pairing, argc, argv);
  if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

  element_init_Zr(s, pairing);
  element_init_Zr(r1, pairing);
  element_init_Zr(r2, pairing);

  element_init_G1(P, pairing);
  element_init_G1(P0, pairing);
  element_init_G1(Q1, pairing);
  element_init_G1(Q2, pairing);
  element_init_G1(Pr1, pairing);
  element_init_G1(Pr2, pairing);
  element_init_G1(Sai1, pairing);
  element_init_G1(Sai2, pairing);
  element_init_G1(temp1, pairing);
  element_init_G1(temp2, pairing);
  element_init_G1(temp3, pairing);
  element_init_G1(tmp1, pairing);
  element_init_G1(tmp2, pairing);
  //element_init_G1(lhs, pairing);
  //element_init_G1(rhs, pairing);
  element_init_G1(X, pairing);
  element_init_G1(sig1, pairing);
  element_init_G1(sig2, pairing);
  
  element_init_G1(hash1, pairing);
  element_init_G1(hash2, pairing);

  element_init_GT(Kab, pairing);
  element_init_GT(Kba, pairing);
  element_init_GT(K, pairing);
  element_init_GT(temp4, pairing);
  element_init_GT(temp5, pairing);
  element_init_GT(lhs, pairing);
  element_init_GT(rhs, pairing);
  printf("\n2PAKA key agreement protocol \n\n");

  t0 = pbc_get_time();

//Setup, system parameters generation
  printf("---SETUP STAGE---\n\n");
  element_random(P);
  element_printf("P = %B\n\n", P);
  element_random(s);
  element_mul_zn(P0, P, s);
  element_printf("P0 = %B\n\n", P0);

//Extract, key calculation
  printf("---EXTRACT STAGE---\n");
  element_from_hash(Q1, "A", 1);
  element_from_hash(Q2, "B", 1);
  printf("Hash on IDs done\n\n");
 
  
 //Pri added
  element_mul_zn(tmp1, s, P);
  element_add(tmp2, s, Q1);
  element_div(Pr1, tmp1, tmp2);
  
  element_mul_zn(tmp1, s, P);
  element_add(tmp2, s, Q2);
  element_div(Pr2, tmp1, tmp2); 
  //
  
 //element_mul_zn(Sa, Q1, s);
 //element_mul_zn(Sb, Q2, s);
  element_printf("Pr1 = %B\n\n", Pr1);
  element_printf("Pr2 = %B\n\n", Pr2);	
  
  printf("-----1-----\n\n");

  element_random(r1);
  element_mul_zn(Sai1, P, r1);
  element_printf("A sends B \u03A81 = %B\n\n", Sai1);
  
  element_mul_zn(sig1, Pr1, r1);
  element_printf("A sends B \u03C31 = %B\n\n", sig1);
  
  printf("-----2-----\n\n");

  element_random(r2);
  element_mul_zn(Sai2, P, r2);
  element_printf("B sends A \u03A82 = %B\n\n", Sai2);
	
  element_mul_zn(sig2, Pr2, r2);
  element_printf("B sends A \u03C32 = %B\n\n", sig2);
  
  printf("-----2.5-----\n\n");
  
  printf(" e'(\u03C32, P0 + Q2.P) == e'(\u03A82, P0) \n");
  //We check condition e^(sig2, P0 + Q2.P) == e^(Sai2, P0)
  element_mul_zn(tmp1, Q2, P);
  element_add(tmp2, P0, tmp1);
  element_pairing(lhs, sig2, tmp2);
  
  element_pairing(rhs, Sai2, P0);
   
  element_printf("A lhs = %B\n\n", lhs);
  element_printf("A rhs = %B\n", rhs);
  printf("\ncmp value = %d i.e.,",element_cmp(lhs,rhs));
  if(!element_cmp(lhs,rhs))
  	printf(" Equal \n");
  else
  	printf(" Not Equal \n");
  printf("-----3-----\n\n");
  
  
 
  printf("A calculates X and sk1\n");
  element_mul_zn(X, Sai2, r1);
  element_printf("X = %B\n", X);

  
  //sk = "A" || "B" || Sai1 || Sai2 || X;
  printf("\nsk = H(ID1 || ID2 || \u03A81 || \u03A82 || X)\n");
  
  
  //done by abhinavg
  
  element_set_str(Sai1, "element in string format",16);
  element_set_str(Sai2, "element in string format",16);
  element_set_str(X, "element in string format",16);
  
  // Determine the required buffer size for the string representation
  size_t str1_size = element_length_in_bytes(Sai1) *2 ; // Multiply by 2 to accommodate hexadecimal representation
  size_t str2_size = element_length_in_bytes(Sai2) *2 ;
  size_t str3_size = element_length_in_bytes(X) *2 ;
  
  // Allocate memory for the string representation
  char* str1 = (char*)malloc(str1_size * sizeof(char));
  char* str2 = (char*)malloc(str2_size * sizeof(char));
  char* str3 = (char*)malloc(str3_size * sizeof(char));
  
  // Convert the element to its string representation
  element_snprintf(str1, str1_size, "%B", Sai1);
  element_snprintf(str2, str2_size, "%B", Sai2);
  element_snprintf(str3, str3_size, "%B", X); 
  
  //initializing str
  size_t total = str1_size + str2_size + str3_size + 1;
  char* str = (char*)malloc( total* sizeof(char));
  strcpy(str,"A");
  		
  strcat(str,"B");
  strcat(str,str1);  
  strcat(str,str2);
  strcat(str,str3);
  
  element_from_hash(hash1, str, sizeof(str));
  
  element_printf("sk1: %B\n\n",hash1);
  //
  
  printf("Now B calculates X and sk2\n");
  element_mul_zn(X, Sai1, r2);
  element_printf("X = %B\n\n", X);


	//********  Must be done again in B's system  *********
  /*element_set_str(Sai1, "element in string format",16);
  element_set_str(Sai2, "element in string format",16);
  element_set_str(X, "element in string format",16);
  
  // Determine the required buffer size for the string representation
  size_t str1_size = element_length_in_bytes(Sai1) *2 ; // Multiply by 2 to accommodate hexadecimal representation
  size_t str2_size = element_length_in_bytes(Sai2) *2 ;
  size_t str3_size = element_length_in_bytes(X) *2 ;
  
  // Allocate memory for the string representation
  char* str1 = (char*)malloc(str1_size * sizeof(char));
  char* str2 = (char*)malloc(str2_size * sizeof(char));
  char* str3 = (char*)malloc(str3_size * sizeof(char));
  
  // Convert the element to its string representation
  element_snprintf(str1, str1_size, "%B", Sai1);
  element_snprintf(str2, str2_size, "%B", Sai2);
  element_snprintf(str3, str3_size, "%B", X); 
  
  //initializing str
  size_t total = str1_size + str2_size + str3_size + 1;
  char* str = (char*)malloc( total* sizeof(char));
  strcpy(str,"A");
  		
  strcat(str,"B");
  strcat(str,str1);  
  strcat(str,str2);
  strcat(str,str3);
  */
  
  
  element_from_hash(hash2, str, sizeof(str));
  
  element_printf("sk2: %B\n\n",hash2);

  if (!element_cmp(hash1, hash2))
    printf("The keys are the same. Start session...\n");
  else
    printf("The keys aren't the same. Try again, please.\n");
    
  element_clear(K);
  element_clear(Kab);
  element_clear(Kba);
  element_clear(X);
  element_clear(temp1);
  element_clear(temp2);
  element_clear(temp3);
  element_clear(temp4);
  element_clear(temp5);
  element_clear(tmp1);
  element_clear(tmp2);
  element_clear(s);
  element_clear(r1);
  element_clear(r2);
  element_clear(P);
  element_clear(P0);
  element_clear(Q1);
  element_clear(Q2);
  element_clear(Pr1);
  element_clear(Pr2);
  element_clear(Sai1);
  element_clear(Sai2);

  t1 = pbc_get_time();

  printf("All time = %fs\n", t1 - t0);
  printf("Have a good day!\n");

  return 0;
}
