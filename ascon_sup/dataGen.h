#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#define TEXTLENGTH 16

/*
Set the following three prameters as fixed length for testing:
plaintext: 16 Bytes
ciphertext: 16 Bytes + 16 Bytes tag
associated data: 16 Bytes

Set nonce and key as constant for testing:
nonce: 16 Bytes
key: 16 Bytes

*/
void prepare_text(char * plaintext, char * ad,int size) {

    srand((unsigned int)time(NULL));

    for (int i = 0; i < TEXTLENGTH*size; i++) {
        plaintext[i] = (unsigned char)(rand() % 256);
    }

    for (int i = 0; i < TEXTLENGTH*size; i++) {
        ad[i] = (unsigned char)(rand() % 256);
    }

    

    return ;

}



//Test case
// int main(){
//     char plaintext[TEXTLENGTH*TExTSIZE];
//     char ad[TEXTLENGTH*TExTSIZE];
//     prepare_data(plaintext, ad);
    
//     printf("plaintext: %c\n ad:%c\n", plaintext[0], ad[0]);
//     return 0;
// }

void prepare_key_nonce(char * key, char * nonce) {

    srand((unsigned int)time(NULL));

    for (int i = 0; i < 16; i++) {
        key[i] = (unsigned char)(rand() % 256);
    }

    for (int i = 0; i < 16; i++) {
        nonce[i] = (unsigned char)(rand() % 256);
    }

    return;

}