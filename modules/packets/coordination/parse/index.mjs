import {
    LENGTH_COORDINATION_HEADER,
    LENGTH_KEY_DECRYPTION,
    LENGTH_KEY_SYMMETRIC,
    LENGTH_SHARED_REMAINDER,
    LENGTH_SHARED_SECRET,

    OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_PORT,
    OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_HOST,

    OFFSET_COORDINATION_TYPE,

    OFFSET_CHECKSUM,

    OFFSET_FORWARD_IPV6_WEBSOCKET_PORT,
    OFFSET_FORWARD_IPV6_WEBSOCKET_HOST,

    OFFSET_KEY_COLOR_CHANGE,
    OFFSET_KEY_DECRYPTION,

    OFFSET_LENGTH_REAL,
    OFFSET_LENGTH_NEXT,

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

import {
    EXTRACT_HOST_IPV6,
    EXTRACT_SUBARRAY,
    EXTRACT_UINT16,
    POLYNOMIAL_HEADER_CHECKSUM,
} from '../../../utilities/index.mjs';

////////////////////////////////////////////////////////////////////////
// TYPE-SPECIFIC PARSE HELPERS                                        //
////////////////////////////////////////////////////////////////////////

const PARSE_REPLY_IPV6 = (reply, binary) => {

    const host = EXTRACT_HOST_IPV6(binary, OFFSET_REPLY_IPV6_HOST);
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

    const host = EXTRACT_HOST_IPV6(binary, OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_HOST);
    const port = EXTRACT_UINT16(binary, OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_PORT);
    text.destination = { host, port };

};

const PARSE_COORDINATION_FORWARD_IPV6_WEBSOCKET = (binary, text) => {

    const host = EXTRACT_HOST_IPV6(binary, OFFSET_FORWARD_IPV6_WEBSOCKET_HOST);
    const port = EXTRACT_UINT16(binary, OFFSET_FORWARD_IPV6_WEBSOCKET_PORT);
    text.destination = { host, port };

};

const PARSE_COORDINATION_REDIRECT_STATIC_IPV6_WEBSOCKET = (binary, text) => {

    const host = EXTRACT_HOST_IPV6(binary, OFFSET_REDIRECT_STATIC_IPV6_WEBSOCKET_HOST);
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

    const subarrayKeyColorChange = EXTRACT_SUBARRAY(
        binary,
        OFFSET_KEY_COLOR_CHANGE,
        LENGTH_KEY_SYMMETRIC,
    );

    text.keyColorChange = new Uint8Array(subarrayKeyColorChange);

    text.shiftTimeIdle = binary[OFFSET_SHIFT_TIME_IDLE];
    text.shiftTimeTotal = binary[OFFSET_SHIFT_TIME_TOTAL];
    text.shiftDataAverage = binary[OFFSET_SHIFT_DATA_AVERAGE];
    text.shiftDataTotal = binary[OFFSET_SHIFT_DATA_TOTAL];

    PARSE_REPLY(binary, text);

};

export const parse = (binary) => {

    const text = {};

    if (binary.length < LENGTH_COORDINATION_HEADER) {

        return null;

    }

    const checksumA = EXTRACT_UINT16(binary, OFFSET_CHECKSUM);
    const checksumB = POLYNOMIAL_HEADER_CHECKSUM(binary);
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
