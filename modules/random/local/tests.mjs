import RandomGenerator from './index.mjs';

import { expect } from 'chai';

const POPULATION_COUNT = (buffer) => {

    let count = 0;

    const { length } = buffer;
    let index = 0;
    while (index < length) {

        let octet = buffer[index];
        index = (index + 1) | 0;

        while (octet !== 0) {

            octet = octet & ((octet - 1) | 0);
            count = (count + 1) | 0;

        }

    }

    return count;

};

const LIMIT_TESTS_A = 2048;
const LIMIT_TESTS_B = 32;
const LIMIT_TESTS_C = 32;

// if the population count of bits is within 40%~60%, let's call it a pass.
const EXPECTED_RANGE_A = 819;
const EXPECTED_RANGE_B = 1229;

describe('RandomGenerator', () => {

    it('should generate bits with equal probability', () => {

        const randomGenerator = RandomGenerator.create();

        const seed = new Uint16Array(16);
        const buffer = new Uint8Array(256);

        let test = 0;
        while (test < LIMIT_TESTS_A) {

            test = (test + 1) | 0;

            for (let index = 0; index < 16; index = (index + 1) | 0) {

                if (index % 2 === 0) {

                    seed[index] = performance.now();

                } else {

                    seed[index] = Math.random() * (1 << 18);

                }

            }

            randomGenerator.seed(seed);

            randomGenerator.fill(buffer);

            const populationCount = POPULATION_COUNT(buffer);
            expect(populationCount).to.be.greaterThan(EXPECTED_RANGE_A);
            expect(populationCount).to.be.lessThan(EXPECTED_RANGE_B);

        }

    });

    it('should deterministically generate bits given a seed', () => {

        const randomGenerator = RandomGenerator.create();

        const seedA = new Uint16Array(16);
        const seedB = new Uint16Array(16);
        const bufferA = new Uint8Array(256);
        const bufferB = new Uint8Array(256);

        let test = 0;
        while (test < LIMIT_TESTS_B) {

            test = (test + 1) | 0;

            for (let index = 0; index < 16; index = (index + 1) | 0) {

                if (index % 2 === 0) {

                    seedA[index] = performance.now();

                } else {

                    seedA[index] = Math.random() * (1 << 18);

                }

            }

            // two equal seeds should produce the same random bits

            seedB.set(seedA);

            randomGenerator.seed(seedA);
            randomGenerator.fill(bufferA);

            randomGenerator.seed(seedB);
            randomGenerator.fill(bufferB);

            for (let index = 0; index < 256; index = (index + 1) | 0) {

                expect(bufferA[index]).to.be.equal(bufferB[index]);

            }

        }

    });

    it('should save and load states', () => {

        const randomGenerator = RandomGenerator.create();
        const seed = new Uint16Array(16);
        
        const bufferA = new Uint8Array(256);
        const bufferB = new Uint8Array(256);

        let test = 0;
        while (test < LIMIT_TESTS_C) {

            test = (test + 1) | 0;

            for (let index = 0; index < 16; index = (index + 1) | 0) {

                if (index % 2 === 0) {

                    seed[index] = performance.now();

                } else {

                    seed[index] = Math.random() * (1 << 18);

                }

            }

            randomGenerator.seed(seed);

            randomGenerator.fill(bufferA);
            randomGenerator.fill(bufferB);

            // saving and loading should produce the same random bits

            const state = randomGenerator.save();
            randomGenerator.fill(bufferA);

            randomGenerator.load(state);
            randomGenerator.fill(bufferB);

            for (let index = 0; index < 256; index = (index + 1) | 0) {

                expect(bufferA[index]).to.be.equal(bufferB[index]);

            }

        }

    });

});
