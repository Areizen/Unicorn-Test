#include <stdio.h>

char* random_crypto(char* cleartext){
    char* base_addr = cleartext;
    
    while(*cleartext != 0 ){
        *cleartext = *cleartext ^ 0x1;
        cleartext++;
    }
    
    return base_addr;
}

int main(int argc, char** argv){
    
    if(argc < 2){
        printf("Usage : %s <data to cipher>\n", argv[0]);
        return -1;
    }

    printf("%s\n", random_crypto(argv[1]));
    return 0;
}