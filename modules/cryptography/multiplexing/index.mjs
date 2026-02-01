import {
    LENGTH_SHARED_REMAINDER,
    LENGTH_SHARED_SECRET,
    MODULUS_SHARED_SECRET,
} from "../../constants/index.mjs";

import {
    POLYNOMIAL_MODULUS_BUFFER_LONG,
} from "../../utilities/index.mjs";

const match = (sharedSecret, remainderA, handshake) => {

    const polynomialSum = new Uint8Array(LENGTH_SHARED_SECRET);

    let index = 0;
    while (index < LENGTH_SHARED_SECRET) {

        polynomialSum[index] = sharedSecret[index] ^ handshake[index];
        index = (index + 1) | 0;

    }

    const remainderB = new Uint8Array(LENGTH_SHARED_REMAINDER);

    POLYNOMIAL_MODULUS_BUFFER_LONG(
        polynomialSum,
        0,
        polynomialSum.length,
        MODULUS_SHARED_SECRET,
        remainderB,
    );

    index = 0;
    while (index < LENGTH_SHARED_REMAINDER) {

        if (remainderA[index] !== remainderB[index]) {

            return false;

        }

        index = (index + 1) | 0;

    }

    return true;

};

const MultiplexingCryptography = Object.freeze({
    match,
});

export default MultiplexingCryptography;
