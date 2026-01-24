import {
    LENGTH_COORDINATION_HEADER,
    LENGTH_HOST_IPV6,

    MODULUS_PACKET_CHECKSUM,

    OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_HOST,
    OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_PORT,

    OFFSET_CHECKSUM,

    OFFSET_FORWARD_IPV6_WEBSOCKET_PORT,
    OFFSET_FORWARD_IPV6_WEBSOCKET_HOST,

    OFFSET_KEY_DECRYPTION,

    OFFSET_LENGTH_REAL,
    OFFSET_LENGTH_NEXT,

    OFFSET_POLYNOMIAL,

    OFFSET_REDIRECT_STATIC_IPV6_WEBSOCKET_HOST,
    OFFSET_REDIRECT_STATIC_IPV6_WEBSOCKET_PORT,

    OFFSET_REMAINDER_DECRYPTION,
    OFFSET_REMAINDER_ENCRYPTION,

    OFFSET_REPLY_IPV6_HOST,
    OFFSET_REPLY_IPV6_PORT,
    OFFSET_REPLY_TYPE,

    OFFSET_SHIFT_DATA_AVERAGE,
    OFFSET_SHIFT_DATA_TOTAL,
    OFFSET_SHIFT_TIME_IDLE,
    OFFSET_SHIFT_TIME_TOTAL,

    OFFSET_SHARED_SECRET_DECRYPTION,
    OFFSET_SHARED_SECRET_ENCRYPTION,

    OFFSET_COORDINATION_TYPE,

    REPLY_TYPE_IPV6_UDP,

    TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET,
    TYPE_COORDINATION_REDIRECT_STATIC_IPV6_WEBSOCKET,
    TYPE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET,
} from '../../../constants/index.mjs';

////////////////////////////////////////////////////////////////////////
// POLYNOMIAL ARITHMETIC                                              //
////////////////////////////////////////////////////////////////////////

const POLYNOMIAL_DEGREE = (polynomial) => (31 - Math.clz32(polynomial)) | 0;

const CALCULATE_HEADER_CHECKSUM = (buffer) => {

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

////////////////////////////////////////////////////////////////////////
// MISCELLANEOUS HELPERS                                              //
////////////////////////////////////////////////////////////////////////

const INSERT_UINT16 = (binary, offset, integer) => {

    binary[(offset + 0) | 0] = (integer >> 8) & 0xFF;
    binary[(offset + 1) | 0] = (integer >> 0) & 0xFF;

};

const INSERT_IPV6 = (binary, offset, address) => {

    binary.fill(0, offset, (offset + LENGTH_HOST_IPV6) | 0);

    const [partA, partB] = address.split('::');

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

////////////////////////////////////////////////////////////////////////
// TYPE-SPECIFIC FORMAT HELPERS                                       //
////////////////////////////////////////////////////////////////////////

const FORMAT_REPLY_IPV6 = (reply, binary) => {

    const { destination } = reply;
    const { host, port } = destination;

    INSERT_UINT16(binary, OFFSET_REPLY_IPV6_PORT, port);
    INSERT_IPV6(binary, OFFSET_REPLY_IPV6_HOST, host);

};

const FORMAT_REPLY = (reply, binary) => {

    const { type } = reply;
    binary[OFFSET_REPLY_TYPE] = type;

    switch (type) {

        case REPLY_TYPE_IPV6_UDP: {

            FORMAT_REPLY_IPV6(reply, binary);
            break;

        }

    }

};

const FORMAT_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET = (text, binary) => {

    const { destination } = text;
    const { host, port } = destination;

    INSERT_UINT16(binary, OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_PORT, port);
    INSERT_IPV6(binary, OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_HOST, host);

};

const FORMAT_COORDINATION_FORWARD_IPV6_WEBSOCKET = (text, binary) => {

    const { destination } = text;
    const { host, port } = destination;

    INSERT_UINT16(binary, OFFSET_FORWARD_IPV6_WEBSOCKET_PORT, port);
    INSERT_IPV6(binary, OFFSET_FORWARD_IPV6_WEBSOCKET_HOST, host);

};

const FORMAT_COORDINATION_REDIRECT_STATIC_IPV6_WEBSOCKET = (text, binary) => {

    const { destination } = text;
    const { host, port } = destination;

    INSERT_UINT16(binary, OFFSET_REDIRECT_STATIC_IPV6_WEBSOCKET_PORT, port);
    INSERT_IPV6(binary, OFFSET_REDIRECT_STATIC_IPV6_WEBSOCKET_HOST, host);

    const { sharedSecretDecryption, remainderDecryption } = text;
    binary.set(sharedSecretDecryption, OFFSET_SHARED_SECRET_DECRYPTION);
    binary.set(remainderDecryption, OFFSET_REMAINDER_DECRYPTION);

    const { sharedSecretEncryption, remainderEncryption } = text;
    binary.set(sharedSecretEncryption, OFFSET_SHARED_SECRET_ENCRYPTION);
    binary.set(remainderEncryption, OFFSET_REMAINDER_ENCRYPTION);

    const { shiftTimeIdle, shiftTimeTotal } = text;
    binary[OFFSET_SHIFT_TIME_IDLE] = shiftTimeIdle;
    binary[OFFSET_SHIFT_TIME_TOTAL] = shiftTimeTotal;

    const { shiftDataAverage, shiftDataTotal } = text;
    binary[OFFSET_SHIFT_DATA_AVERAGE] = shiftDataAverage;
    binary[OFFSET_SHIFT_DATA_TOTAL] = shiftDataTotal;

    const { reply } = text;
    FORMAT_REPLY(reply, binary);

};

////////////////////////////////////////////////////////////////////////
// EXPORTED PROCEDURES                                                //
////////////////////////////////////////////////////////////////////////

const format = (text, binary) => {

    const { type, key, lengthReal, lengthNext } = text;

    binary[OFFSET_COORDINATION_TYPE] = type;
    INSERT_UINT16(binary, OFFSET_LENGTH_REAL, lengthReal);
    INSERT_UINT16(binary, OFFSET_LENGTH_NEXT, lengthNext);

    binary.set(key, OFFSET_KEY_DECRYPTION);

    switch (type) {

        case TYPE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET: {

            FORMAT_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET(text, binary);
            break;

        }

        case TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET: {

            FORMAT_COORDINATION_FORWARD_IPV6_WEBSOCKET(text, binary);
            break;

        }

        case TYPE_COORDINATION_REDIRECT_STATIC_IPV6_WEBSOCKET: {

            FORMAT_COORDINATION_REDIRECT_STATIC_IPV6_WEBSOCKET(text, binary);
            break;

        }

    }

    const checksum = CALCULATE_HEADER_CHECKSUM(binary);
    INSERT_UINT16(binary, OFFSET_CHECKSUM, checksum);

};

const CoordinationPackets = Object.freeze({
    format,
});

export default CoordinationPackets;
