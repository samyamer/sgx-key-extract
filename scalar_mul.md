## IPP Scalar Mult walkthrough

Say we have a 256-bit nonce K written as an array of 8 bit integers in little endian format.\
```
static const Ipp8u k[]          = { 0xde,0x68,0x2a,0x64,0x87,0x07,0x67,0xb9,0x33,0x5d,0x4f,0x82,0x47,0x62,0x4a,0x3b,
                                    0x7f,0x3c,0xe9,0xf9,0x45,0xf2,0x80,0xa2,0x61,0x6a,0x90,0x4b,0xb1,0xbb,0xa1,0x94 };
```
So in human readable format K is :
0x94a1bbb14b...............de

Where 0x94 is the most significant byte and de is the least significant byte.

The window slicing goes as follows:

- We number the bits of K from 1..256 (yes 1). where 256 is the most significant.
- We track the index of the least significant bit OF THE CURRENT WINDOW (bit)

We start at the most significant of K. with bit =255

\As an edge case for the first window we zero extend K so that bits following bit 255 fit the window (see diagram).

''' 

    bit = 255
    while bit >=5
        wvalue = k[bit:bit+6] (yes 6) // so for bit 250 the wvalue will be made of bit 255,254,253,252,251,250. With 255 as the most significant
        // This means that the least significant bit of the previous window is the most significant bit of the current window (this is an overlap)
        bit -=5

        sign, digit = booth_recode(wvalue)
        // sign and digit is what has been recovered 
'''

We are left with the edge case of the final window. Since the last iteration of the loop is at bit 5, bits 1,2,3,and 4 are not yet included in the multiplication. Their window value is taken as:

'''
    wvalue=k[1:6] // bit 5,4,3,2,1 (again the most significant is bit 5, which is the overlap)

The windows for our k example are as such:
Again, Bit denotes the starting index of the window with the bits indexed from 1 to 256 with 256 as the most significant.

| Bit      | Wvalue (hex) |
|----------|----------|
| 255   | 2  |
| 250   | a  |
| 245   | a  |
| 240   | 3  |
| 235   | 2E  |
| 230   | 1D  |
| 225   | 31  |
| 220   | 29  |


Take Bit 235, the window corresponding with it has a wvalue of 2E. This is due to the overlapping bit discussed above. Without this overlapping bit it would just be E. The overlapping bit doesn't make a difference in windows 255, 250, and 245 simply because its 0.

### LA Recovery
Since we recover the sign,digit in the order they are processed, the first recovered belong to the most significant bits and so on.

![alt text](https://github.com/samyamer/sgx-key-extract/blob/main/IMG_2550.jpg)

![alt text](https://github.com/samyamer/sgx-key-extract/blob/main/Screenshot%20From%202025-01-29%2018-29-28.png)
