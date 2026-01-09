import ElGamalCryptography from '../cryptography/elgamal/index.mjs';
import TwofishCryptography from '../cryptography/twofish/index.mjs';

import { WebSocketServer, WebSocket } from 'ws';

const LENGTH_HEADER = 256; // octets, also known as "bytes"
const LENGTH_IPV6_ADDRESS = 16; // octets, also known as "bytes"
const LENGTH_KEY = 256; // octets, also known as "bytes"

const OFFSET_HEADER = 0;
const OFFSET_KEY_SENDER = LENGTH_HEADER;
const OFFSET_DATA_START = LENGTH_HEADER + LENGTH_KEY;

const OFFSET_TYPE                                               = 2;
const OFFSET_LENGTH_REAL                                        = 236;
const OFFSET_KEY_DECRYPTION                                     = 240;

const OFFSET_FORWARD_IPV6_WEBSOCKET_PORT                        = 4;
const OFFSET_FORWARD_IPV6_WEBSOCKET_ADDRESS                     = 16;

const TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET                  = 3;

// uses network byte order (big-endian) for integers
const EXTRACT_UINT16 = (buffer, offset) => {

    let accumulator = 0;
    accumulator = accumulator | ((buffer[(offset + 0) | 0]) << 8);
    accumulator = accumulator | ((buffer[(offset + 1) | 0]) << 0);

    return accumulator;

};

const EXTRACT_IPV6_ADDRESS = (buffer, offset) => {

    const chunks = [];

    const limit = (offset + LENGTH_IPV6_ADDRESS) | 0;
    let index = offset;
    while (index < limit) {

        let word = 0;
        word = word | (buffer[index | 0] << 8);
        word = word | (buffer[index | 1] << 0);

        index = (index + 2) | 0;

        const chunk = word.toString(16);
        chunks.push(chunk);

    }

    const address = chunks.join(':');
    return address;

};

const EXTRACT_SUBARRAY = (buffer, offset, length) => {

    return buffer.subarray(offset, (offset + length) | 0);

}

////////////////////////////////////////////////////////////////////////
// HANDLERS FOR EACH MESSAGE TYPE                                     //
////////////////////////////////////////////////////////////////////////

const HANDLE_COORDINATION_FORWARD_IPV6_WEBSOCKET = (message) => {

    const remoteHost = EXTRACT_IPV6_ADDRESS(message, OFFSET_FORWARD_IPV6_WEBSOCKET_ADDRESS);
    const remotePort = EXTRACT_UINT16(message, OFFSET_FORWARD_IPV6_WEBSOCKET_PORT);

    const sendMessage = (remoteHost, remotePort, packet) => {

        const target = `ws://[${ remoteHost }]:${ remotePort }/`;

        const webSocket = new WebSocket(target, {
            perMessageDeflate: false
        });

        webSocket.on('error', (error) => {

            console.log(error);

        });

        webSocket.on('open', () => {

            webSocket.send(packet);

            setTimeout(() => {

                webSocket.close();

            }, 1000);

        });

    };

    const packet = message.subarray(OFFSET_DATA_START);
    sendMessage(remoteHost, remotePort, packet);

};

////////////////////////////////////////////////////////////////////////
// CREATORS FOR EACH ROUTER TYPE                                      //
////////////////////////////////////////////////////////////////////////

const CREATE_COORDINATION_SERVER_WEBSOCKET = (options) => {

    const { exponent, coordination } = options;
    const { host, port } = coordination;

    const server = new WebSocketServer({ host, port });

    server.on('connection', (socket) => {

        socket.on('message', (message) => {

            const keySender = EXTRACT_SUBARRAY(message, OFFSET_KEY_SENDER, LENGTH_KEY);
            const textPlainA = new Uint8Array(LENGTH_KEY);
            const textCipherA = message.subarray(0, LENGTH_HEADER);
            ElGamalCryptography.decrypt2048(
                exponent,
                keySender,
                textCipherA,
                textPlainA,
            );

            message.set(textPlainA, OFFSET_HEADER);

            const lengthData = EXTRACT_UINT16(textPlainA, OFFSET_LENGTH_REAL);

            const key = textPlainA.subarray(OFFSET_KEY_DECRYPTION);
            const textPlainB = new Uint8Array(lengthData);
            const textCipherB = message.subarray(OFFSET_DATA_START);
            TwofishCryptography.decrypt128(key, textCipherB, textPlainB);

            message.set(textPlainB, OFFSET_DATA_START);

            const type = message[OFFSET_TYPE];
            switch (type) {

                case TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET: {

                    return HANDLE_COORDINATION_FORWARD_IPV6_WEBSOCKET(message);

                }

            }

        });

    });

    return server;

};

const createServer = (options) => {

    let serverCoordination = null;

    const { coordination } = options;
    const { type: coordinationType } = coordination;

    switch (coordinationType) {

        case 'websocket': {

            serverCoordination = CREATE_COORDINATION_SERVER_WEBSOCKET(options);

        }

    }

    const address = () => {

        return serverCoordination.address();

    };

    const close = () => {

        serverCoordination.close();

    };

    const router = Object.freeze({
        address,
        close,
    });

    return router;

};

const AnonymityRouter = Object.freeze({
    createServer,
});

export default AnonymityRouter;
