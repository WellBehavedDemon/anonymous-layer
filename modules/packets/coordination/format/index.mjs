import {
    LENGTH_COORDINATION_HEADER,
    LENGTH_HOST_IPV6,

    MODULUS_PACKET_CHECKSUM,

    OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_HOST,
    OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_PORT,

    OFFSET_CHECKSUM,

    OFFSET_FORWARD_IPV6_WEBSOCKET_PORT,
    OFFSET_FORWARD_IPV6_WEBSOCKET_HOST,

    OFFSET_KEY_COLOR_CHANGE,
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

import {
    INSERT_HOST_IPV6,
    INSERT_UINT16,
    POLYNOMIAL_HEADER_CHECKSUM,
} from '../../../utilities/index.mjs';

////////////////////////////////////////////////////////////////////////
// TYPE-SPECIFIC FORMAT HELPERS                                       //
////////////////////////////////////////////////////////////////////////

const FORMAT_REPLY_IPV6 = (reply, binary) => {

    const { destination } = reply;
    const { host, port } = destination;

    INSERT_UINT16(binary, OFFSET_REPLY_IPV6_PORT, port);
    INSERT_HOST_IPV6(binary, OFFSET_REPLY_IPV6_HOST, host);

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
    INSERT_HOST_IPV6(binary, OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_HOST, host);

};

const FORMAT_COORDINATION_FORWARD_IPV6_WEBSOCKET = (text, binary) => {

    const { destination } = text;
    const { host, port } = destination;

    INSERT_UINT16(binary, OFFSET_FORWARD_IPV6_WEBSOCKET_PORT, port);
    INSERT_HOST_IPV6(binary, OFFSET_FORWARD_IPV6_WEBSOCKET_HOST, host);

};

const FORMAT_COORDINATION_REDIRECT_STATIC_IPV6_WEBSOCKET = (text, binary) => {

    const { destination } = text;
    const { host, port } = destination;

    INSERT_UINT16(binary, OFFSET_REDIRECT_STATIC_IPV6_WEBSOCKET_PORT, port);
    INSERT_HOST_IPV6(binary, OFFSET_REDIRECT_STATIC_IPV6_WEBSOCKET_HOST, host);

    const { sharedSecretDecryption, remainderDecryption } = text;
    binary.set(sharedSecretDecryption, OFFSET_SHARED_SECRET_DECRYPTION);
    binary.set(remainderDecryption, OFFSET_REMAINDER_DECRYPTION);

    const { sharedSecretEncryption, remainderEncryption } = text;
    binary.set(sharedSecretEncryption, OFFSET_SHARED_SECRET_ENCRYPTION);
    binary.set(remainderEncryption, OFFSET_REMAINDER_ENCRYPTION);

    const { keyColorChange } = text;
    binary.set(keyColorChange, OFFSET_KEY_COLOR_CHANGE);

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

export const format = (text, binary) => {

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

    const checksum = POLYNOMIAL_HEADER_CHECKSUM(binary);
    INSERT_UINT16(binary, OFFSET_CHECKSUM, checksum);

};

const CoordinationPackets = Object.freeze({
    format,
});

export default CoordinationPackets;
