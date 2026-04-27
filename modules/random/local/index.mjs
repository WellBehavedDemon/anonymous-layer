import {
    MASK_MODULUS_EIGHT,
    MASK_MODULUS_FOUR,
    POLYNOMIAL_BITS16,
    POLYNOMIAL_BITS6,
    POLYNOMIALS_BITS8,
} from '../../constants/index.mjs';

import {
    POLYNOMIAL_MODULAR_REMAINDER,
} from '../../utilities/index.mjs';

const create = () => {

    const internalSeed = new Uint16Array(16);

    let indexA = 0x0;
    let indexB = 0x4;
    let indexC = 0x8;
    let indexD = 0xC;

    let chosenPolynomial = 0;

    const generateOctet = () => {

        const wordA = internalSeed[indexA];
        const wordB = internalSeed[indexB];
        const wordC = internalSeed[indexC];
        const wordD = internalSeed[indexD];

        const addendA = (wordA + ((wordB << 2) | 1));
        const addendB = (wordC + ((wordD << 2) | 3));
        const sum = addendA ^ addendB;

        const randomWord = POLYNOMIAL_MODULAR_REMAINDER(sum, POLYNOMIAL_BITS16);

        internalSeed[indexA] = randomWord ^ (~wordB);
        internalSeed[indexB] = randomWord ^ (~wordC);
        internalSeed[indexC] = randomWord ^ (~wordD);
        internalSeed[indexD] = randomWord ^ (~wordA);

        const polynomial = POLYNOMIALS_BITS8[chosenPolynomial];
        const randomOctet = POLYNOMIAL_MODULAR_REMAINDER(randomWord, polynomial);

        indexA = indexA ^ ((randomOctet >>> 0) & MASK_MODULUS_FOUR);
        indexB = indexB ^ ((randomOctet >>> 2) & MASK_MODULUS_FOUR);
        indexC = indexC ^ ((randomOctet >>> 4) & MASK_MODULUS_FOUR);
        indexD = indexD ^ ((randomOctet >>> 6) & MASK_MODULUS_FOUR);

        const stride = POLYNOMIAL_MODULAR_REMAINDER(randomOctet, POLYNOMIAL_BITS6);

        chosenPolynomial = (chosenPolynomial + (stride >>> 3)) | 0;
        chosenPolynomial = (chosenPolynomial ^ (stride >>> 0)) | 0;
        chosenPolynomial = chosenPolynomial & MASK_MODULUS_EIGHT;

        return randomOctet;

    };

    const fill = (buffer) => {

        const { length } = buffer;
        let index = 0;
        while (index < length) {

            buffer[index] = generateOctet();
            index = (index + 1) | 0;

        }

    };

    const load = (state) => {

        internalSeed.set(state.seed);

        indexA = state.indexA;
        indexB = state.indexB;
        indexC = state.indexC;
        indexD = state.indexD;

        chosenPolynomial = state.chosenPolynomial;

    };

    const save = () => {

        const exportedSeed = new Uint16Array(16);
        exportedSeed.set(internalSeed);

        const state = Object.freeze({
            seed: exportedSeed,
            indexA: indexA,
            indexB: indexB,
            indexC: indexC,
            indexD: indexD,
            chosenPolynomial: chosenPolynomial,
        });

        return state;

    };

    const seed = (input) => {

        internalSeed.set(input);

        indexA = 0b0000;
        indexB = 0b0100;
        indexC = 0b1000;
        indexD = 0b1100;

        chosenPolynomial = 0;

    };

    const skip = (units) => {

        while (units > 0) {

            units = (units - 1) | 0;
            generateOctet();

        }

    };

    const localRandomGenerator = Object.freeze({
        fill,
        load,
        save,
        seed,
        skip,
    });

    return localRandomGenerator;

};

const RandomGenerator = Object.freeze({
    create,
});

export default RandomGenerator;
