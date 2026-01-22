const LENGTH_HEADER = 256; // octets, also known as "bytes"
const LENGTH_IPV6_ADDRESS = 16; // octets, also known as "bytes"
const LENGTH_KEY_DECRYPTION = 16; // octets, also known as "bytes"
const LENGTH_REMAINDER = 8; // octets, also known as "bytes"
const LENGTH_SHARED_SECRET = 16; // octets, also known as "bytes"

////////////////////////////////////////////////////////////////////////
// POLYNOMIAL ARITHMETIC                                              //
////////////////////////////////////////////////////////////////////////

// polynomial modulus for packet checksum
// expression: x^17 + x^3 + 1
// binary: 0b10000000000001001
const PACKET_CHECKSUM_MODULUS = 0b10000000000001001;

const POLYNOMIAL_DEGREE = (polynomial) => (31 - Math.clz32(polynomial)) | 0;

const OFFSET_POLYNOMIAL = 2;
const CALCULATE_HEADER_CHECKSUM = (buffer) => {

    let accumulator = 0;
    let index = OFFSET_POLYNOMIAL;
    while (index < LENGTH_HEADER) {

        accumulator = (accumulator << 8) | buffer[index];

        const degreeModulus = POLYNOMIAL_DEGREE(PACKET_CHECKSUM_MODULUS);
        let degreePolynomial = POLYNOMIAL_DEGREE(accumulator);
        while (degreePolynomial >= degreeModulus) {

            const shift = (degreePolynomial - degreeModulus) | 0;
            const subtractor = PACKET_CHECKSUM_MODULUS << shift;
            accumulator = accumulator ^ subtractor;

            degreePolynomial = POLYNOMIAL_DEGREE(accumulator);

        }

        index = (index + 1) | 0;

    }

    return accumulator;

};

////////////////////////////////////////////////////////////////////////
// OFFSETS                                                            //
////////////////////////////////////////////////////////////////////////

const OFFSET_CHECKSUM                                           = 0;
const OFFSET_TYPE                                               = 2;
const OFFSET_REPLY_TYPE                                         = 3;
const OFFSET_SHIFT_TIME_IDLE                                    = 4;
const OFFSET_SHIFT_TIME_TOTAL                                   = 5;
const OFFSET_SHIFT_DATA_AVERAGE                                 = 6;
const OFFSET_SHIFT_DATA_TOTAL                                   = 7;
const OFFSET_LENGTH_REAL                                        = 236;
const OFFSET_LENGTH_NEXT                                        = 238;
const OFFSET_KEY_DECRYPTION                                     = 240;

const OFFSET_REPLY_IPV6_PORT                                    = 14;
const OFFSET_REPLY_IPV6_HOST                                    = 32;

const OFFSET_SHARED_SECRET_DECRYPTION                           = 48;
const OFFSET_SHARED_SECRET_ENCRYPTION                           = 64;
const OFFSET_REMAINDER_DECRYPTION                               = 80;
const OFFSET_REMAINDER_ENCRYPTION                               = 88;

const OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_PORT                  = 12;
const OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_ADDRESS               = 16;

const OFFSET_FORWARD_IPV6_WEBSOCKET_PORT                        = 12;
const OFFSET_FORWARD_IPV6_WEBSOCKET_ADDRESS                     = 16;

const OFFSET_REDIRECT_IPV6_WEBSOCKET_PORT                       = 12;
const OFFSET_REDIRECT_IPV6_WEBSOCKET_ADDRESS                    = 16;

////////////////////////////////////////////////////////////////////////
// MISCELLANEOUS HELPERS                                              //
////////////////////////////////////////////////////////////////////////

const EXTRACT_IPV6_ADDRESS = (buffer, offset) => {

    const chunks = [];

    const limit = (offset + LENGTH_IPV6_ADDRESS) | 0;
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
// TYPES                                                              //
////////////////////////////////////////////////////////////////////////

const TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET                  = 2;

const TYPE_COORDINATION_REDIRECT_IPV6_WEBSOCKET                 = 6;

const TYPE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET            = 14;

const REPLY_TYPE_IPV6_UDP                                       = 3;

////////////////////////////////////////////////////////////////////////
// TYPE-SPECIFIC PARSE HELPERS                                        //
////////////////////////////////////////////////////////////////////////

const PARSE_REPLY_IPV6 = (reply, binary) => {

    const host = EXTRACT_IPV6_ADDRESS(binary, OFFSET_REPLY_IPV6_HOST);
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

    const host = EXTRACT_IPV6_ADDRESS(binary, OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_ADDRESS);
    const port = EXTRACT_UINT16(binary, OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_PORT);
    text.destination = { host, port };

};

const PARSE_COORDINATION_FORWARD_IPV6_WEBSOCKET = (binary, text) => {

    const host = EXTRACT_IPV6_ADDRESS(binary, OFFSET_FORWARD_IPV6_WEBSOCKET_ADDRESS);
    const port = EXTRACT_UINT16(binary, OFFSET_FORWARD_IPV6_WEBSOCKET_PORT);
    text.destination = { host, port };

};

const PARSE_COORDINATION_REDIRECT_IPV6_WEBSOCKET = (binary, text) => {

    const host = EXTRACT_IPV6_ADDRESS(binary, OFFSET_REDIRECT_IPV6_WEBSOCKET_ADDRESS);
    const port = EXTRACT_UINT16(binary, OFFSET_REDIRECT_IPV6_WEBSOCKET_PORT);
    text.destination = { host, port };

    const subarrayRemainderDecryption = EXTRACT_SUBARRAY(
        binary,
        OFFSET_REMAINDER_DECRYPTION,
        LENGTH_REMAINDER,
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
        LENGTH_REMAINDER,
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

    if (binary.length < LENGTH_HEADER) {

        return null;

    }

    const checksumA = EXTRACT_UINT16(binary, OFFSET_CHECKSUM);
    const checksumB = CALCULATE_HEADER_CHECKSUM(binary);
    if (checksumA !== checksumB) {

        return null;

    }

    text.type = binary[OFFSET_TYPE];
    switch (text.type) {

        case TYPE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET: {

            PARSE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET(binary, text);
            break;

        }

        case TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET: {

            PARSE_COORDINATION_FORWARD_IPV6_WEBSOCKET(binary, text);
            break;

        }

        case TYPE_COORDINATION_REDIRECT_IPV6_WEBSOCKET: {

            PARSE_COORDINATION_REDIRECT_IPV6_WEBSOCKET(binary, text);
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
