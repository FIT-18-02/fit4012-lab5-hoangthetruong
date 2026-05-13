#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>

#include "structures.h"

using namespace std;

/* XOR state với round key */
void AddRoundKey(unsigned char * state, unsigned char * roundKey)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] ^= roundKey[i];
    }
}

/* Thay byte qua S-box */
void SubBytes(unsigned char * state)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] = s[state[i]];
    }
}

/* ShiftRows */
void ShiftRows(unsigned char * state)
{
    unsigned char tmp[16];

    tmp[0]  = state[0];
    tmp[1]  = state[5];
    tmp[2]  = state[10];
    tmp[3]  = state[15];

    tmp[4]  = state[4];
    tmp[5]  = state[9];
    tmp[6]  = state[14];
    tmp[7]  = state[3];

    tmp[8]  = state[8];
    tmp[9]  = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];

    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];

    for (int i = 0; i < 16; i++)
    {
        state[i] = tmp[i];
    }
}

/* MixColumns */
void MixColumns(unsigned char * state)
{
    unsigned char tmp[16];

    tmp[0]  = mul2[state[0]]  ^ mul3[state[1]]  ^ state[2]  ^ state[3];
    tmp[1]  = state[0]        ^ mul2[state[1]]  ^ mul3[state[2]] ^ state[3];
    tmp[2]  = state[0]        ^ state[1]        ^ mul2[state[2]] ^ mul3[state[3]];
    tmp[3]  = mul3[state[0]]  ^ state[1]        ^ state[2]  ^ mul2[state[3]];

    tmp[4]  = mul2[state[4]]  ^ mul3[state[5]]  ^ state[6]  ^ state[7];
    tmp[5]  = state[4]        ^ mul2[state[5]]  ^ mul3[state[6]] ^ state[7];
    tmp[6]  = state[4]        ^ state[5]        ^ mul2[state[6]] ^ mul3[state[7]];
    tmp[7]  = mul3[state[4]]  ^ state[5]        ^ state[6]  ^ mul2[state[7]];

    tmp[8]  = mul2[state[8]]  ^ mul3[state[9]]  ^ state[10] ^ state[11];
    tmp[9]  = state[8]        ^ mul2[state[9]]  ^ mul3[state[10]] ^ state[11];
    tmp[10] = state[8]        ^ state[9]        ^ mul2[state[10]] ^ mul3[state[11]];
    tmp[11] = mul3[state[8]]  ^ state[9]        ^ state[10] ^ mul2[state[11]];

    tmp[12] = mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15];
    tmp[13] = state[12]       ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15];
    tmp[14] = state[12]       ^ state[13]       ^ mul2[state[14]] ^ mul3[state[15]];
    tmp[15] = mul3[state[12]] ^ state[13]       ^ state[14] ^ mul2[state[15]];

    for (int i = 0; i < 16; i++)
    {
        state[i] = tmp[i];
    }
}

/* Main AES round */
void Round(unsigned char * state, unsigned char * key)
{
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, key);
}

/* Final round */
void FinalRound(unsigned char * state, unsigned char * key)
{
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, key);
}

/* AES encrypt 1 block */
void AESEncrypt(
    unsigned char * message,
    unsigned char * expandedKey,
    unsigned char * encryptedMessage)
{
    unsigned char state[16];

    for (int i = 0; i < 16; i++)
    {
        state[i] = message[i];
    }

    AddRoundKey(state, expandedKey);

    for (int i = 0; i < 9; i++)
    {
        Round(state, expandedKey + (16 * (i + 1)));
    }

    FinalRound(state, expandedKey + 160);

    for (int i = 0; i < 16; i++)
    {
        encryptedMessage[i] = state[i];
    }
}

int main()
{
    cout << "=============================" << endl;
    cout << " AES-128 Encryption Tool " << endl;
    cout << "=============================" << endl;

    char message[1024];

    cout << "Enter plaintext: ";

    cin.getline(message, sizeof(message));

    int originalLen = strlen(message);

    int paddedLen = originalLen;

    if (paddedLen % 16 != 0)
    {
        paddedLen =
            ((paddedLen / 16) + 1) * 16;
    }

    unsigned char * paddedMessage =
        new unsigned char[paddedLen];

    for (int i = 0; i < paddedLen; i++)
    {
        if (i >= originalLen)
            paddedMessage[i] = 0x00;
        else
            paddedMessage[i] = message[i];
    }

    unsigned char * encryptedMessage =
        new unsigned char[paddedLen];

    /* Read key */
    ifstream infile("keyfile");

    string str;

    getline(infile, str);

    infile.close();

    unsigned char key[16];

    for (int i = 0; i < 16; i++)
    {
        string byteString =
            str.substr(i * 2, 2);

        key[i] =
            (unsigned char)
            strtol(byteString.c_str(), nullptr, 16);
    }

    unsigned char expandedKey[176];

    KeyExpansion(key, expandedKey);

    /* Encrypt từng block */
    for (int i = 0; i < paddedLen; i += 16)
    {
        AESEncrypt(
            paddedMessage + i,
            expandedKey,
            encryptedMessage + i
        );
    }

    cout << "\nCiphertext (hex):\n";

    for (int i = 0; i < paddedLen; i++)
    {
        cout
            << hex
            << setw(2)
            << setfill('0')
            << (int)encryptedMessage[i];
    }

    cout << endl;

    /* Ghi binary đúng */
    ofstream outfile(
        "message.aes",
        ios::binary
    );

    if (outfile.is_open())
    {
        outfile.write(
            (char*)encryptedMessage,
            paddedLen
        );

        outfile.close();

        cout << "\nSaved to message.aes\n";
    }
    else
    {
        cout << "Cannot open output file\n";
    }

    delete[] paddedMessage;
    delete[] encryptedMessage;

    return 0;
}
