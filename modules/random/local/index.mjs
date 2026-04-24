const POLYNOMIAL_DEGREE = (polynomial) => (31 - Math.clz32(polynomial)) | 0;

const POLYNOMIAL_MODULAR_REMAINDER = (dividend, divisor) => {

    const degreeDivisor = POLYNOMIAL_DEGREE(divisor);
    let degreeDividend = POLYNOMIAL_DEGREE(dividend);
    while (degreeDividend >= degreeDivisor) {

        const shift = (degreeDividend - degreeDivisor) | 0;
        const subtractor = divisor << shift;
        dividend = dividend ^ subtractor;

        degreeDividend = POLYNOMIAL_DEGREE(dividend);

    }

    return dividend;

};

const MASK_MODULUS_FOUR = 0b11;
const MASK_MODULUS_EIGHT = 0b111;

// expression: x^16 + x^14 + x^10 + x^8 + x^3 + x^1 + 1
// binary: 0b10100010100001011
const POLYNOMIAL_BITS16 = 0b10100010100001011;

// expression: x^6 + x^5 + x^3 + x^2 + 1
// binary: 0b1101101
const POLYNOMIAL_BITS6 = 0b1101101;

const POLYNOMIALS_BITS8 = new Uint32Array([
    0b100011101, // x^8 + x^4 + x^3 + x^2 + 1
    0b100101011, // x^8 + x^5 + x^3 + x^1 + 1
    0b101011111, // x^8 + x^6 + x^4 + x^3 + x^2 + x^1 + 1
    0b101100011, // x^8 + x^6 + x^5 + x^1 + 1
    0b101100101, // x^8 + x^6 + x^5 + x^2 + 1
    0b100000011, // x^8 + x^6 + x^5 + x^3 + 1
    0b100000011, // x^8 + x^7 + x^6 + x^1 + 1
    0b100000011, // x^8 + x^7 + x^6 + x^5 + x^2 + x^1 + 1
]);

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

    const localRandomGenerator = Object.freeze({
        fill,
        load,
        save,
        seed,
    });

    return localRandomGenerator;

};

const RandomGenerator = Object.freeze({
    create,
});

export default RandomGenerator;
