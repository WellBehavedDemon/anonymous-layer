import {
    LENGTH_COORDINATION_HEADER,
    LENGTH_HOST_IPV6,
    MODULUS_PACKET_CHECKSUM,
    OFFSET_POLYNOMIAL,
} from '../constants/index.mjs';

////////////////////////////////////////////////////////////////////////
// EXTRACTION                                                         //
////////////////////////////////////////////////////////////////////////

export const EXTRACT_HOST_IPV6 = (buffer, offset) => {

    const chunks = [];

    const limit = (offset + LENGTH_HOST_IPV6) | 0;
    let index = offset;
    while (index < limit) {

        let word = 0;
        word = word | (buffer[index | 0] << 8);
        word = word | (buffer[index | 1] << 0);

        index = (index + 2) | 0;

        const chunk = word.toString(16).padStart(4, '0');
        chunks.push(chunk);

    }

    const address = chunks.join(':');
    return address;

};

export const EXTRACT_SUBARRAY = (buffer, offset, length) => {

    return buffer.subarray(offset, (offset + length) | 0);

}

// uses network byte order (big-endian) for integers
export const EXTRACT_UINT16 = (buffer, offset) => {

    let accumulator = 0;
    accumulator = accumulator | ((buffer[(offset + 0) | 0]) << 8);
    accumulator = accumulator | ((buffer[(offset + 1) | 0]) << 0);

    return accumulator;

};

////////////////////////////////////////////////////////////////////////
// INSERTION                                                          //
////////////////////////////////////////////////////////////////////////

export const INSERT_HOST_IPV6 = (binary, offset, host) => {

    binary.fill(0, offset, (offset + LENGTH_HOST_IPV6) | 0);

    const [partA, partB] = host.split('::');

    if (partA) {

        const chunks = partA.split(':');
        let subOffset = offset;

        const { length } = chunks;
        let index = 0;
        while (index < length) {

            const chunk = chunks[index];
            const integer = Number.parseInt(chunk, 16);
            INSERT_UINT16(binary, subOffset, integer);

            index = (index + 1) | 0;
            subOffset = (subOffset + 2) | 0;

        }

    }

    if (partB) {

        const chunks = partB.split(':');
        let subOffset = (offset + LENGTH_HOST_IPV6) | 0;

        const { length } = chunks;
        let index = length;
        while (index > 0) {

            index = (index - 1) | 0;
            subOffset = (subOffset - 2) | 0;

            const chunk = chunks[index];
            const integer = Number.parseInt(chunk, 16);
            INSERT_UINT16(binary, subOffset, integer);

        }

    }

};

export const INSERT_UINT16 = (binary, offset, integer) => {

    binary[(offset + 0) | 0] = (integer >> 8) & 0xFF;
    binary[(offset + 1) | 0] = (integer >> 0) & 0xFF;

};

////////////////////////////////////////////////////////////////////////
// POLYNOMIAL ARITHMETIC                                              //
////////////////////////////////////////////////////////////////////////

export const POLYNOMIAL_DEGREE = (polynomial) => (31 - Math.clz32(polynomial)) | 0;

export const POLYNOMIAL_MODULUS_BUFFER = (buffer, offset, length, modulus) => {

    const degreeModulus = POLYNOMIAL_DEGREE(modulus);

    let accumulator = 0;
    let index = offset;
    while (index < length) {

        accumulator = (accumulator << 8) | buffer[index];

        let degreePolynomial = POLYNOMIAL_DEGREE(accumulator);
        while (degreePolynomial >= degreeModulus) {

            const shift = (degreePolynomial - degreeModulus) | 0;
            const subtractor = modulus << shift;
            accumulator = accumulator ^ subtractor;

            degreePolynomial = POLYNOMIAL_DEGREE(accumulator);

        }

        index = (index + 1) | 0;

    }

    return accumulator;

};

export const POLYNOMIAL_HEADER_CHECKSUM = (buffer) => {

    let accumulator = 0;
    let index = OFFSET_POLYNOMIAL;
    while (index < LENGTH_COORDINATION_HEADER) {

        accumulator = (accumulator << 8) | buffer[index];

        const degreeModulus = POLYNOMIAL_DEGREE(MODULUS_PACKET_CHECKSUM);
        let degreePolynomial = POLYNOMIAL_DEGREE(accumulator);
        while (degreePolynomial >= degreeModulus) {

            const shift = (degreePolynomial - degreeModulus) | 0;
            const subtractor = MODULUS_PACKET_CHECKSUM << shift;
            accumulator = accumulator ^ subtractor;

            degreePolynomial = POLYNOMIAL_DEGREE(accumulator);

        }

        index = (index + 1) | 0;

    }

    return accumulator;

};
