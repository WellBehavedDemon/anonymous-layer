import ElGamalCryptography from '../cryptography/elgamal/index.mjs';
import TwofishCryptography from '../cryptography/twofish/index.mjs';

import { WebSocketServer, WebSocket } from 'ws';

import {
    LENGTH_COORDINATION_HEADER,
    LENGTH_COORDINATION_KEY,

    OFFSET_COORDINATION_HEADER,
    OFFSET_COORDINATION_TYPE,
    OFFSET_FORWARD_IPV6_WEBSOCKET_PORT,
    OFFSET_FORWARD_IPV6_WEBSOCKET_HOST,
    OFFSET_KEY_DECRYPTION,
    OFFSET_LENGTH_REAL,

    TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET,
} from '../constants/index.mjs';

import {
    EXTRACT_HOST_IPV6,
    EXTRACT_SUBARRAY,
    EXTRACT_UINT16,
} from '../utilities/index.mjs'

const OFFSET_KEY_SENDER = LENGTH_COORDINATION_HEADER;
const OFFSET_DATA_START = LENGTH_COORDINATION_HEADER + LENGTH_COORDINATION_KEY;

////////////////////////////////////////////////////////////////////////
// HANDLERS FOR EACH MESSAGE TYPE                                     //
////////////////////////////////////////////////////////////////////////

const HANDLE_COORDINATION_FORWARD_IPV6_WEBSOCKET = (message) => {

    const remoteHost = EXTRACT_HOST_IPV6(message, OFFSET_FORWARD_IPV6_WEBSOCKET_HOST);
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

            const keySender = EXTRACT_SUBARRAY(message, OFFSET_KEY_SENDER, LENGTH_COORDINATION_KEY);
            const textPlainA = new Uint8Array(LENGTH_COORDINATION_KEY);
            const textCipherA = message.subarray(0, LENGTH_COORDINATION_HEADER);
            ElGamalCryptography.decrypt2048(
                exponent,
                keySender,
                textCipherA,
                textPlainA,
            );

            message.set(textPlainA, OFFSET_COORDINATION_HEADER);

            const lengthData = EXTRACT_UINT16(textPlainA, OFFSET_LENGTH_REAL);

            const key = textPlainA.subarray(OFFSET_KEY_DECRYPTION);
            const textPlainB = new Uint8Array(lengthData);
            const textCipherB = message.subarray(OFFSET_DATA_START);
            TwofishCryptography.decrypt128(key, textCipherB, textPlainB);

            message.set(textPlainB, OFFSET_DATA_START);

            const type = message[OFFSET_COORDINATION_TYPE];
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
