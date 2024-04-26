#include <stdio.h>

// unsigned char RawData_Ping[] = {
//        /*---- wlan header start -----*/
//        0x88,                                /* version , type sub type */
//        0x02,                                /* Frame control flag */
//        0x2C, 0x00,
//        0x00, 0x23, 0x75, 0x55,0x55, 0x55,   /* destination */
//        0x00, 0x22, 0x75, 0x55,0x55, 0x55,   /* bssid */
//        0x08, 0x00, 0x28, 0x19,0x02, 0x85,   /* source */
//        0x80, 0x42, 0x00, 0x00,
//        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, /* LLC */
//        /*---- ip header start -----*/
//        0x45, 0x00, 0x00, 0x54, 0x96, 0xA1, 0x00, 0x00, 0x40, 0x01,
//        0x57, 0xFA,                          /* checksum */
//        0xc0, 0xa8, 0x01, 0x64,              /* src ip */
//        0xc0, 0xa8, 0x01, 0x02,              /* dest ip  */
//        /* payload - ping/icmp */
//        0x08, 0x00, 0xA5, 0x51,
//        0x5E, 0x18, 0x00, 0x00, 0x41, 0x08, 0xBB, 0x8D, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00};
void modPacketMACSource(char* RawPacket, char* modification);
void modPacketMACDest(char* RawPacket, char* modification);
void modPacketPayload(char* RawPacket, char* modification, char from);
void extractMACSource(char* RawPacket, char* MACSource);
void extractMACDest(char* RawPacket, char* MACDest);
void extractPayload(char* RawPacket, char* payLoad);
void extractFromTo(char* RawPacket, char* extraction, unsigned char from, unsigned char to);

int main(){

    char RawData_Ping[] = {
    /*---- wlan header start -----*/
    0, /* version , type sub type */
    1, /* Frame control flag */
    2, 3,
    4, 5, 6, 7, 8, 9, /* destination */
    10, 11, 12, 13, 14, 15, /* bssid */
    16, 17, 18, 19, 20, 21, /* source */
    22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, /* LLC */
    /*---- ip header start -----*/
    34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
    44, 45, /* checksum */
    46, 47, 48, 49, /* src ip */
    50, 51, 52, 53, /* dest ip  */
    /* payload - ping/icmp */
    54, 55, 56, 57,
    58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69,
    70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81,
    82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93,
    94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105,
    106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
    118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
    130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141,
    142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153,
    154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
    166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177,
    178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189,
    190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201,
    202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213,
    214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225,
    226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237,
    238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249,
    250, 251, 252, 253, 254, 255
    };


    int packetLength = sizeof(RawData_Ping); //each element is 1 byte

    printf("packet has %i elements \n", packetLength);

    // Payload mod test
    // char payloadMod[] = {0xAA, 0xBB, 0xCC, 0xDD};
    // modPacketPayload(RawData_Ping, payloadMod, 54);
    // printf("PAYLOAD = %02x, %02x, %02x, %02x, %02x \n", RawData_Ping[54],
    //      RawData_Ping[55], RawData_Ping[56], RawData_Ping[57], RawData_Ping[58]);

    char source[6];
    char dest[6];
    unsigned char payLoad[201];
    unsigned char extraction[256];

    unsigned char from = 0, to = 255;

    extractMACSource(RawData_Ping, source);
    extractMACDest(RawData_Ping, dest);
    extractPayload(RawData_Ping, payLoad);
    extractFromTo(RawData_Ping, extraction, from, to);

    unsigned char i;
    for (i = 0; i < 6; i++)
        printf("source[%i] = %i \n", i, source[i]);

    for (i = 0; i < 6; i++)
        printf("dest[%i] = %i \n", i, dest[i]);

    for (i = 0; i < 202; i++)
        printf("payLoad[%i] = %i \n", i, payLoad[i]);

    for (i = 0; i < to - from + 1; i++)
        printf("extraction[%i] = %i \n", i, extraction[i]);
    return 0;

    /* PRINT ASCII TABLE
    int i;
    for (i = 0; i < 128; i++)
        printf("%i is %c \n", i, RawData_Ping[i]);
    */
   
}

// modification has to be 5 bytes (elements) long
void modPacketMACSource(char* RawPacket, char* modification){
    unsigned char i;
    for (i = 0; i <= 5; i++){
        RawPacket[16 + i] = modification[i];
    }
}

// modification has to be 5 bytes (elements) long
void modPacketMACDest(char* RawPacket, char* modification){
    unsigned char i;
    for (i = 0; i <= 5; i++){
        RawPacket[4 + i] = modification[i];
    }
}

// This function figures out how long the modification is to the payload.
void modPacketPayload(char* RawPacket, char* modification, char from){
    unsigned char i;
    for (char i = 0; i < sizeof(modification); i++){
        RawPacket[from + i] = modification[i];
    }
}

void extractMACSource(char* RawPacket, char* MACSource){
    unsigned char i;

    for(i = 0; i <= 5; i++){
        MACSource[i] = RawPacket[16 + i];
    }
    
}

void extractMACDest(char* RawPacket, char* MACDest){
    unsigned char i;

    for(i = 0; i <= 5; i++){
        MACDest[i] = RawPacket[4 + i];
    }
}

void extractPayload(char* RawPacket, char* payLoad){
    unsigned char i;

    for(i = 0; i <= 201; i++){
        payLoad[i] = RawPacket[54 + i];
    }

}

// Use indices of where you want to extract
void extractFromTo(char* RawPacket, char* extraction, unsigned char from, unsigned char to){
    unsigned char i;

    for(i = 0; i <= to - from; i++){
        extraction[i] = RawPacket[from + i];
    }
}

