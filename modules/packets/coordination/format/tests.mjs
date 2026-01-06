import CoordinationPackets from './index.mjs';

import { expect } from 'chai';

const LENGTH_HEADER = 256; // octets, also known as "bytes"

// length in octets for the symmetric cryptography key (128-bits)
const LENGTH_KEY = 16; // octets, also known as "bytes"

// all defined types for coordination packets
const TYPE_COORDINATION_FORWARD_IPV4_WEBSOCKET                  = 1;
const TYPE_COORDINATION_FORWARD_IPV4_UDP                        = 2;
const TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET                  = 3;
const TYPE_COORDINATION_FORWARD_IPV6_UDP                        = 4;

// offsets that are common for coordination packets of any type
// offset #0 is where the checksum is stored
// offset #2 is where the octets that are the dividend begin
// offset #236 is wehre the real length (header not included) is stored
// offset #238 is where the next length (header not included) is stored
// offset #240 is where the decryption key is stored

const OFFSET_CHECKSUM                                           = 0;
const OFFSET_TYPE                                               = 2;
const OFFSET_LENGTH_REAL                                        = 236;
const OFFSET_LENGTH_NEXT                                        = 238;
const OFFSET_KEY_DECRIPTION                                     = 240;

// offsets for TYPE_COORDINATION_FORWARD_IPV4_WEBSOCKET

const OFFSET_FORWARD_IPV4_WEBSOCKET_PORT                        = 4;
const OFFSET_FORWARD_IPV4_WEBSOCKET_ADDRESS                     = 8;

// offsets for TYPE_COORDINATION_FORWARD_IPV4_UDP

const OFFSET_FORWARD_IPV4_UDP_PORT                              = 4;
const OFFSET_FORWARD_IPV4_UDP_ADDRESS                           = 8;

// offsets for TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET

const OFFSET_FORWARD_IPV6_WEBSOCKET_PORT                        = 4;
const OFFSET_FORWARD_IPV6_WEBSOCKET_ADDRESS                     = 16;

// offsets for TYPE_COORDINATION_FORWARD_IPV6_UDP

const OFFSET_FORWARD_IPV6_UDP_PORT                              = 4;
const OFFSET_FORWARD_IPV6_UDP_ADDRESS                           = 16;

// polynomial modulus for packet checksum
// expression: x^17 + x^3 + 1
// binary: 0b10000000000001001
const PACKET_CHECKSUM_MODULUS = 0b10000000000001001;

// uses network byte order (big-endian) for integers
const EXTRACT_UINT16 = (buffer, offset) => {

    let accumulator = 0;
    accumulator = accumulator | ((buffer[(offset + 0) | 0]) << 8);
    accumulator = accumulator | ((buffer[(offset + 1) | 0]) << 0);

    return accumulator;

};

describe('CoordinationPackets', () => {

    const POLYNOMIAL_DEGREE = (polynomial) => (31 - Math.clz32(polynomial)) | 0;

    const BUFFER_POLYNOMIAL_MODULUS = (buffer, offset, length, modulus) => {

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

    const COMMON_HEADER_CHECK = (buffer, typeA, keyA, lengthRealA, lengthNextA) => {

        // 128-bits symmetric cryptography key
        expect(keyA).to.have.lengthOf(16);

        // 16-bits for any length
        expect(lengthRealA).to.be.lessThan(1 << 16).and.greaterThanOrEqual(0);
        expect(lengthNextA).to.be.lessThan(1 << 16).and.greaterThanOrEqual(0);

        const typeB = buffer[OFFSET_TYPE];
        expect(typeA).to.equal(typeB);

        const lengthRealB = EXTRACT_UINT16(buffer, OFFSET_LENGTH_REAL);
        const lengthNextB = EXTRACT_UINT16(buffer, OFFSET_LENGTH_NEXT);
        expect(lengthRealA).to.equal(lengthRealB);
        expect(lengthNextA).to.equal(lengthNextB);

        const keyB = buffer.subarray(
            OFFSET_KEY_DECRIPTION,
            (OFFSET_KEY_DECRIPTION + LENGTH_KEY) | 0,
        );

        let index = 0;
        while (index < LENGTH_KEY) {

            const keyDataA = keyA[index];
            const keyDataB = keyB[index];
            expect(keyDataA).to.equal(keyDataB);

            index = (index + 1) | 0;

        }

        const checksumA = EXTRACT_UINT16(buffer, OFFSET_CHECKSUM);

        const checksumB = BUFFER_POLYNOMIAL_MODULUS(
            buffer,
            2, // offset where the dividend octets start
            LENGTH_HEADER,
            PACKET_CHECKSUM_MODULUS,
        );

        expect(checksumA).to.equal(checksumB);

    };

    const TEST_CASES_A = Object.freeze([
        {
            text: {
                type: TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET,
                key: new Uint8Array([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                ]),
                lengthReal: 0x1A85,
                lengthNext: 0x351D,
                destination: Object.freeze({
                    host: '::1',
                    port: 11412, // 0x2C94
                }),
            },
            binary: new Uint8Array([
                0x52, 0x99, 0x03, 0x00, 0x2C, 0x94, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x1A, 0x85, 0x35, 0x1D,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            ]),
        },
        {
            text: {
                type: TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET,
                key: new Uint8Array([
                    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
                ]),
                lengthReal: 0x0123,
                lengthNext: 0x0456,
                destination: Object.freeze({
                    host: '2804:187c:81cb:6800:31b7:9570:6f8f:a3b6',
                    port: 11412, // 0x2C94
                }),
            },
            binary: new Uint8Array([
                0xEF, 0x9C, 0x03, 0x00, 0x2C, 0x94, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x28, 0x04, 0x18, 0x7C, 0x81, 0xCB, 0x68, 0x00,
                0x31, 0xB7, 0x95, 0x70, 0x6F, 0x8F, 0xA3, 0xB6,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x23, 0x04, 0x56,
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
            ]),
        },
    ]);

    it('should format text objects into binary packets', () => {

        for (const request of TEST_CASES_A) {

            const { text, binary: binaryA } = request;

            const {
                type: typeA,
                key: keyA,
                lengthReal: lengthRealA,
                lengthNext: lengthNextA,
            } = text;

            const binaryB = new Uint8Array(LENGTH_HEADER);

            CoordinationPackets.format(text, binaryB);

            COMMON_HEADER_CHECK(
                binaryB,
                typeA,
                keyA,
                lengthRealA,
                lengthNextA,
            );

            let index = 0;
            while (index < LENGTH_HEADER) {

                expect(binaryA[index]).to.equal(binaryB[index]);
                index = (index + 1) | 0;

            }

        }

    });

});
