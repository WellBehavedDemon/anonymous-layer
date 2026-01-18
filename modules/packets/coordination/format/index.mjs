const LENGTH_HEADER = 256; // octets, also known as "bytes"

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
const OFFSET_TIMEOUT_IDLE                                       = 6;
const OFFSET_LENGTH_REAL                                        = 236;
const OFFSET_LENGTH_NEXT                                        = 238;
const OFFSET_KEY_DECRIPTION                                     = 240;

const OFFSET_REPLY_IPV6_PORT                                    = 32 + 4;
const OFFSET_REPLY_IPV6_HOST                                    = 32 + 16;

const OFFSET_SHARED_SECRET                                      = 64 + 0;
const OFFSET_REMAINDER                                          = 64 + 16;

const OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_PORT                  = 4;
const OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_ADDRESS               = 16;

const OFFSET_FORWARD_IPV6_WEBSOCKET_PORT                        = 4;
const OFFSET_FORWARD_IPV6_WEBSOCKET_ADDRESS                     = 16;

const OFFSET_REDIRECT_IPV6_WEBSOCKET_PORT                       = 4;
const OFFSET_REDIRECT_IPV6_WEBSOCKET_ADDRESS                    = 16;

////////////////////////////////////////////////////////////////////////
// TYPES                                                              //
////////////////////////////////////////////////////////////////////////

const TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET                  = 2;

const TYPE_COORDINATION_REDIRECT_IPV6_WEBSOCKET                 = 6;

const TYPE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET            = 14;

const REPLY_TYPE_IPV6_UDP                                       = 3;

////////////////////////////////////////////////////////////////////////
// MISCELLANEOUS HELPERS                                              //
////////////////////////////////////////////////////////////////////////

const INSERT_UINT16 = (binary, offset, integer) => {

    binary[(offset + 0) | 0] = (integer >> 8) & 0xFF;
    binary[(offset + 1) | 0] = (integer >> 0) & 0xFF;

};

const LENGTH_ADDRESS_IPV6 = 16; // octets, also known as "bytes"
const INSERT_IPV6 = (binary, offset, address) => {

    binary.fill(0, offset, (offset + LENGTH_ADDRESS_IPV6) | 0);

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
        let subOffset = (offset + LENGTH_ADDRESS_IPV6) | 0;

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
    INSERT_IPV6(binary, OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_ADDRESS, host);

};

const FORMAT_COORDINATION_FORWARD_IPV6_WEBSOCKET = (text, binary) => {

    const { destination } = text;
    const { host, port } = destination;

    INSERT_UINT16(binary, OFFSET_FORWARD_IPV6_WEBSOCKET_PORT, port);
    INSERT_IPV6(binary, OFFSET_FORWARD_IPV6_WEBSOCKET_ADDRESS, host);

};

const FORMAT_COORDINATION_REDIRECT_IPV6_WEBSOCKET = (text, binary) => {

    const { destination } = text;
    const { host, port } = destination;

    INSERT_UINT16(binary, OFFSET_REDIRECT_IPV6_WEBSOCKET_PORT, port);
    INSERT_IPV6(binary, OFFSET_REDIRECT_IPV6_WEBSOCKET_ADDRESS, host);

    const { sharedSecret, remainder } = text;
    binary.set(sharedSecret, OFFSET_SHARED_SECRET);
    binary.set(remainder, OFFSET_REMAINDER);

    const { timeoutIdle } = text;
    binary[OFFSET_TIMEOUT_IDLE] = timeoutIdle;

    const { reply } = text;
    FORMAT_REPLY(reply, binary);

};


////////////////////////////////////////////////////////////////////////
// EXPORTED PROCEDURES                                                //
////////////////////////////////////////////////////////////////////////

const format = (text, binary) => {

    const { type, key, lengthReal, lengthNext } = text;

    binary[OFFSET_TYPE] = type;
    INSERT_UINT16(binary, OFFSET_LENGTH_REAL, lengthReal);
    INSERT_UINT16(binary, OFFSET_LENGTH_NEXT, lengthNext);

    binary.set(key, OFFSET_KEY_DECRIPTION);

    switch (type) {

        case TYPE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET: {

            FORMAT_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET(text, binary);
            break;

        }

        case TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET: {

            FORMAT_COORDINATION_FORWARD_IPV6_WEBSOCKET(text, binary);
            break;

        }

        case TYPE_COORDINATION_REDIRECT_IPV6_WEBSOCKET: {

            FORMAT_COORDINATION_REDIRECT_IPV6_WEBSOCKET(text, binary);
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
