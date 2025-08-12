#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Basit eğitim amaçlı bir "key" kontrolü. (Saldırı amaçlı değildir.)
static int check(const char* s){
    size_t n = strlen(s);
    if(n != 8) return 0;
    uint8_t k[8] = {0x13,0x37,0x42,0x55,0x90,0xAB,0xCD,0xEF};
    for(size_t i=0;i<8;i++){
        if(((uint8_t)s[i] ^ k[i]) != (uint8_t)(0x20+i)) return 0;
    }
    return 1;
}

int main(){
    char buf[128];
    puts("enter key:");
    if(!fgets(buf, sizeof(buf), stdin)) return 0;
    // satır sonunu kırp
    for(int i=0; buf[i]; ++i){ if(buf[i]=='\n' || buf[i]=='\r'){ buf[i]=0; break; } }
    if(check(buf)) puts("OK"); else puts("NOPE");
    return 0;
}
