## IPP Scalar Mult walkthrough

Say we have a 256-bit nonce K written as an array of 8 bit integers in little endian format.
static const Ipp8u k[]          = { 0xde,0x68,0x2a,0x64,0x87,0x07,0x67,0xb9,0x33,0x5d,0x4f,0x82,0x47,0x62,0x4a,0x3b,
                                    0x7f,0x3c,0xe9,0xf9,0x45,0xf2,0x80,0xa2,0x61,0x6a,0x90,0x4b,0xb1,0xbb,0xa1,0x94 };

So in human readable format K is :
0x94a1bbb14b...............de

Where 0x94 is the most significant byte and de is the least significant byte.

The window slicing goes as follows:

- We number the bits of K from 1..256 (yes 1). where 256 is the mist significant.
- We track the index of the least significant bit OF THE CURRENT WINDOW (bit)

We start at the most significant of K. with bit =255
bit = 255.
As an edge case for the first window we zero extend K so that bits following bit 255 fit the window (see diagram).

'''
while bit >=5
    wvalue = k[bit:bit+6] (yes 6)
    // This means that the least significant bit of the previous window is the most significant bit of the current window (this is an overlap)
    bit -=5

    sign, digit = booth_recode(wvalue)
    // sign and digit is what has been recovered 
'''

![alt text](https://github.com/samyamer/sgx-key-extract/blob/main/IMG_2550.jpg)