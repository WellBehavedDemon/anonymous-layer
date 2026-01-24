import {
    LENGTH_COORDINATION_HEADER,
    LENGTH_HOST_IPV6,
    LENGTH_KEY_DECRYPTION,
    LENGTH_SHARED_REMAINDER,
    LENGTH_SHARED_SECRET,

    MODULUS_PACKET_CHECKSUM,

    OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_PORT,
    OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_HOST,

    OFFSET_COORDINATION_TYPE,

    OFFSET_CHECKSUM,

    OFFSET_FORWARD_IPV6_WEBSOCKET_PORT,
    OFFSET_FORWARD_IPV6_WEBSOCKET_HOST,

    OFFSET_KEY_DECRYPTION,

    OFFSET_LENGTH_REAL,
    OFFSET_LENGTH_NEXT,

    OFFSET_POLYNOMIAL,

    OFFSET_REMAINDER_DECRYPTION,
    OFFSET_REMAINDER_ENCRYPTION,

    OFFSET_REPLY_IPV6_PORT,
    OFFSET_REPLY_IPV6_HOST,
    OFFSET_REPLY_TYPE,

    OFFSET_REDIRECT_STATIC_IPV6_WEBSOCKET_PORT,
    OFFSET_REDIRECT_STATIC_IPV6_WEBSOCKET_HOST,

    OFFSET_SHARED_SECRET_DECRYPTION,
    OFFSET_SHARED_SECRET_ENCRYPTION,

    OFFSET_SHIFT_DATA_AVERAGE,
    OFFSET_SHIFT_DATA_TOTAL,
    OFFSET_SHIFT_TIME_IDLE,
    OFFSET_SHIFT_TIME_TOTAL,

    REPLY_TYPE_IPV6_UDP,

    TYPE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET,
    TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET,
    TYPE_COORDINATION_REDIRECT_STATIC_IPV6_WEBSOCKET,
} from '../../../constants/index.mjs'

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

const EXTRACT_IPV6_HOST = (buffer, offset) => {

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

const EXTRACT_SUBARRAY = (buffer, offset, length) => {

    return buffer.subarray(offset, (offset + length) | 0);

}

// uses network byte order (big-endian) for integers
const EXTRACT_UINT16 = (buffer, offset) => {

    let accumulator = 0;
    accumulator = accumulator | ((buffer[(offset + 0) | 0]) << 8);
    accumulator = accumulator | ((buffer[(offset + 1) | 0]) << 0);

    return accumulator;

};

////////////////////////////////////////////////////////////////////////
// TYPE-SPECIFIC PARSE HELPERS                                        //
////////////////////////////////////////////////////////////////////////

const PARSE_REPLY_IPV6 = (reply, binary) => {

    const host = EXTRACT_IPV6_HOST(binary, OFFSET_REPLY_IPV6_HOST);
    const port = EXTRACT_UINT16(binary, OFFSET_REPLY_IPV6_PORT);
    reply.destination = { host, port };

};

const PARSE_REPLY = (binary, text) => {

    text.reply = {};
    text.reply.type = binary[OFFSET_REPLY_TYPE];

    switch (text.reply.type) {

        case REPLY_TYPE_IPV6_UDP: {

            PARSE_REPLY_IPV6(text.reply, binary);
            break;

        }

    }

};

const PARSE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET = (binary, text) => {

    const host = EXTRACT_IPV6_HOST(binary, OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_HOST);
    const port = EXTRACT_UINT16(binary, OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_PORT);
    text.destination = { host, port };

};

const PARSE_COORDINATION_FORWARD_IPV6_WEBSOCKET = (binary, text) => {

    const host = EXTRACT_IPV6_HOST(binary, OFFSET_FORWARD_IPV6_WEBSOCKET_HOST);
    const port = EXTRACT_UINT16(binary, OFFSET_FORWARD_IPV6_WEBSOCKET_PORT);
    text.destination = { host, port };

};

const PARSE_COORDINATION_REDIRECT_STATIC_IPV6_WEBSOCKET = (binary, text) => {

    const host = EXTRACT_IPV6_HOST(binary, OFFSET_REDIRECT_STATIC_IPV6_WEBSOCKET_HOST);
    const port = EXTRACT_UINT16(binary, OFFSET_REDIRECT_STATIC_IPV6_WEBSOCKET_PORT);
    text.destination = { host, port };

    const subarrayRemainderDecryption = EXTRACT_SUBARRAY(
        binary,
        OFFSET_REMAINDER_DECRYPTION,
        LENGTH_SHARED_REMAINDER,
    );

    const subarraySharedSecretDecryption = EXTRACT_SUBARRAY(
        binary,
        OFFSET_SHARED_SECRET_DECRYPTION,
        LENGTH_SHARED_SECRET,
    );

    text.sharedSecretDecryption = new Uint8Array(subarraySharedSecretDecryption);
    text.remainderDecryption = new Uint8Array(subarrayRemainderDecryption);

    const subarrayRemainderEncryption = EXTRACT_SUBARRAY(
        binary,
        OFFSET_REMAINDER_ENCRYPTION,
        LENGTH_SHARED_REMAINDER,
    );

    const subarraySharedSecretEncryption = EXTRACT_SUBARRAY(
        binary,
        OFFSET_SHARED_SECRET_ENCRYPTION,
        LENGTH_SHARED_SECRET,
    );

    text.sharedSecretEncryption = new Uint8Array(subarraySharedSecretEncryption);
    text.remainderEncryption = new Uint8Array(subarrayRemainderEncryption);

    text.shiftTimeIdle = binary[OFFSET_SHIFT_TIME_IDLE];
    text.shiftTimeTotal = binary[OFFSET_SHIFT_TIME_TOTAL];
    text.shiftDataAverage = binary[OFFSET_SHIFT_DATA_AVERAGE];
    text.shiftDataTotal = binary[OFFSET_SHIFT_DATA_TOTAL];

    PARSE_REPLY(binary, text);

};

const parse = (binary) => {

    const text = {};

    if (binary.length < LENGTH_COORDINATION_HEADER) {

        return null;

    }

    const checksumA = EXTRACT_UINT16(binary, OFFSET_CHECKSUM);
    const checksumB = CALCULATE_HEADER_CHECKSUM(binary);
    if (checksumA !== checksumB) {

        return null;

    }

    text.type = binary[OFFSET_COORDINATION_TYPE];
    switch (text.type) {

        case TYPE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET: {

            PARSE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET(binary, text);
            break;

        }

        case TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET: {

            PARSE_COORDINATION_FORWARD_IPV6_WEBSOCKET(binary, text);
            break;

        }

        case TYPE_COORDINATION_REDIRECT_STATIC_IPV6_WEBSOCKET: {

            PARSE_COORDINATION_REDIRECT_STATIC_IPV6_WEBSOCKET(binary, text);
            break;

        }

        default: {

            return null;

        }

    }

    text.lengthReal = EXTRACT_UINT16(binary, OFFSET_LENGTH_REAL);
    text.lengthNext = EXTRACT_UINT16(binary, OFFSET_LENGTH_NEXT);

    const subarrayKey = EXTRACT_SUBARRAY(
        binary,
        OFFSET_KEY_DECRYPTION,
        LENGTH_KEY_DECRYPTION,
    );

    text.key = new Uint8Array(subarrayKey);

    return text;

};

const CoordinationPackets = Object.freeze({
    parse,
});

export default CoordinationPackets;
