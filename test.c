#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct gcoip_hdr
{
    uint16_t flavour;
    uint8_t texture;
    uint8_t milktype;
    uint8_t coagulation;
    uint8_t  ingredients[];
} __attribute__((packed));

int main(){
    printf("%lu\n", sizeof(struct gcoip_hdr));
}