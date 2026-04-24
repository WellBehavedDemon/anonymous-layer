import {
    MASK_MODULUS_EIGHT,
    MASK_MODULUS_FOUR,
    POLYNOMIALS_BITS8,
} from '../../constants/index.mjs';

import {
    POLYNOMIAL_MODULAR_REMAINDER,
} from '../../utilities/index.mjs';

let chosenPolynomial = 0;

let indexA = 0;
let indexB = 0;
let indexC = 0;
let indexD = 0;

const wordsA = new Uint32Array(4);
const wordsB = new Uint32Array(4);
const wordsC = new Uint32Array(4);
const wordsD = new Uint32Array(4);

const setup = () => {

    let index = 0;
    while (index < 4) {

        wordsA[index] = wordsA[index] ^ ((Math.random() * (1 << 31)) >>> 0);
        wordsB[index] = wordsB[index] ^ ((Math.random() * (1 << 31)) >>> 0);
        wordsC[index] = wordsC[index] ^ ((Math.random() * (1 << 31)) >>> 0);
        wordsD[index] = wordsD[index] ^ ((Math.random() * (1 << 31)) >>> 0);

        generateOctet();

        index = (index + 1) | 0;

    }

};

const generateOctet = () => {

    const wordA = wordsA[indexA];
    const wordB = wordsB[indexB];
    const wordC = wordsC[indexC];
    const wordD = wordsD[indexD];

    const polynomial = POLYNOMIALS_BITS8[chosenPolynomial];
    const randomWord = ((wordC + (wordB | 1)) | 0) ^ (wordA ^ wordD);
    wordsA[indexA] = randomWord ^ (~wordB);
    wordsB[indexB] = randomWord ^ (~wordC);
    wordsC[indexC] = randomWord ^ (~wordD);
    wordsD[indexD] = randomWord ^ (~wordA);

    const randomOctet = POLYNOMIAL_MODULAR_REMAINDER(randomWord, polynomial);

    indexA = (indexA + (randomOctet >>> 0)) & MASK_MODULUS_FOUR;
    indexB = (indexB + (randomOctet >>> 2)) & MASK_MODULUS_FOUR;
    indexC = (indexC + (randomOctet >>> 4)) & MASK_MODULUS_FOUR;
    indexD = (indexD + (randomOctet >>> 6)) & MASK_MODULUS_FOUR;

    chosenPolynomial = (chosenPolynomial + (randomOctet >>> 4)) | 0;
    chosenPolynomial = (chosenPolynomial ^ (randomOctet >>> 0)) | 0;
    chosenPolynomial = chosenPolynomial & MASK_MODULUS_EIGHT;

    return randomOctet;

};

const seed = (number) => {

    let index = 0;
    while (index < 4) {

        wordsA[index] = wordsA[index] ^ number;
        wordsB[index] = wordsB[index] ^ number;
        wordsC[index] = wordsC[index] ^ number;
        wordsD[index] = wordsD[index] ^ number;

        generateOctet();

        index = (index + 1) | 0;

    }

};

const fill = (buffer) => {

    const { length } = buffer;
    let index = 0;
    while (index < length) {

        buffer[index] = generateOctet();
        index = (index + 1) | 0;

    }

};

const RandomGenerator = Object.freeze({
    fill,
    seed,
    setup,
});

setup();

export default RandomGenerator;
