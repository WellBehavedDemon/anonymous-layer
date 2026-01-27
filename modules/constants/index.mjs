////////////////////////////////////////////////////////////////////////
// LENGHTS - all measured in bit octets, also known as "bytes"        //
////////////////////////////////////////////////////////////////////////

export const LENGTH_COORDINATION_HEADER                         = 256;
export const LENGTH_COORDINATION_KEY                            = 256;
export const LENGTH_HOST_IPV6                                   = 16;
export const LENGTH_KEY_DECRYPTION                              = 16;
export const LENGTH_KEY_ENCRYPTION                              = 16;
export const LENGTH_KEY_SYMMETRIC                               = 16;
export const LENGTH_SHARED_REMAINDER                            = 8;
export const LENGTH_SHARED_SECRET                               = 16;

////////////////////////////////////////////////////////////////////////
// LIMITS                                                             //
////////////////////////////////////////////////////////////////////////

export const LIMIT_UINT32_MAX
    = (~0) >>> 0;

////////////////////////////////////////////////////////////////////////
// MODULUS                                                            //
////////////////////////////////////////////////////////////////////////

// polynomial modulus for packet checksum
// expression: x^17 + x^3 + 1
// binary: 0b10000000000001001
export const MODULUS_PACKET_CHECKSUM
    = 0b10000000000001001;

// expression: x^23 + x^5 + 1
// binary: 0b100000000000000000100001
export const MODULUS_PEER_IDENTIFICATION
    = 0b100000000000000000100001;

////////////////////////////////////////////////////////////////////////
// OFFSETS                                                            //
////////////////////////////////////////////////////////////////////////

// offsets that are common for coordination packets of any type
// offset #0 is where the checksum is stored
// offset #2 is where the octets that are the dividend begin
// offset #236 is where the real length (header not included) is stored
// offset #238 is where the next length (header not included) is stored
// offset #240 is where the decryption key is stored

export const OFFSET_CHECKSUM                                    = 0;
export const OFFSET_POLYNOMIAL                                  = 2;
export const OFFSET_COORDINATION_TYPE                           = 2;
export const OFFSET_REPLY_TYPE                                  = 3;
export const OFFSET_SHIFT_TIME_IDLE                             = 4;
export const OFFSET_SHIFT_TIME_TOTAL                            = 5;
export const OFFSET_SHIFT_DATA_AVERAGE                          = 6;
export const OFFSET_SHIFT_DATA_TOTAL                            = 7;
export const OFFSET_FLAGS_32BITS                                = 8;
export const OFFSET_LENGTH_REAL                                 = 236;
export const OFFSET_LENGTH_NEXT                                 = 238;
export const OFFSET_KEY_DECRYPTION                              = 240;

export const OFFSET_REPLY_IPV4_PORT                             = 14;
export const OFFSET_REPLY_IPV4_HOST                             = 16;
export const OFFSET_REPLY_IPV6_PORT                             = 14;
export const OFFSET_REPLY_IPV6_HOST                             = 32;

export const OFFSET_SHARED_SECRET_DECRYPTION                    = 48;
export const OFFSET_SHARED_SECRET_ENCRYPTION                    = 64;
export const OFFSET_REMAINDER_DECRYPTION                        = 80;
export const OFFSET_REMAINDER_ENCRYPTION                        = 88;

export const OFFSET_COORDINATION_HEADER                         = 0;
export const OFFSET_COORDINAITION_KEY_SENDER                    = 256;

// offsets for TYPE_COORDINATION_ANNOUNCE_PEER_IPV4_WEBSOCKET

export const OFFSET_ANNOUNCE_PEER_IPV4_WEBSOCKET_PORT           = 12;
export const OFFSET_ANNOUNCE_PEER_IPV4_WEBSOCKET_HOST           = 16;

// offsets for TYPE_COORDINATION_ANNOUNCE_PEER_IPV4_UDP

export const OFFSET_ANNOUNCE_PEER_IPV4_UDP_PORT                 = 12;
export const OFFSET_ANNOUNCE_PEER_IPV4_UDP_HOST                 = 16;

// offsets for TYPE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET

export const OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_PORT           = 12;
export const OFFSET_ANNOUNCE_PEER_IPV6_WEBSOCKET_HOST           = 16;

// offsets for TYPE_COORDINATION_ANNOUNCE_PEER_IPV6_UDP

export const OFFSET_ANNOUNCE_PEER_IPV6_UDP_PORT                 = 12;
export const OFFSET_ANNOUNCE_PEER_IPV6_UDP_HOST                 = 16;

// offsets for TYPE_COORDINATION_FORWARD_IPV4_WEBSOCKET

export const OFFSET_FORWARD_IPV4_WEBSOCKET_PORT                 = 12;
export const OFFSET_FORWARD_IPV4_WEBSOCKET_HOST                 = 16;

// offsets for TYPE_COORDINATION_FORWARD_IPV4_UDP

export const OFFSET_FORWARD_IPV4_UDP_PORT                       = 12;
export const OFFSET_FORWARD_IPV4_UDP_HOST                       = 16;

// offsets for TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET

export const OFFSET_FORWARD_IPV6_WEBSOCKET_PORT                 = 12;
export const OFFSET_FORWARD_IPV6_WEBSOCKET_HOST                 = 16;

// offsets for TYPE_COORDINATION_FORWARD_IPV6_UDP

export const OFFSET_FORWARD_IPV6_UDP_PORT                       = 12;
export const OFFSET_FORWARD_IPV6_UDP_HOST                       = 16;

// offsets for TYPE_COORDINATION_REDIRECT_STATIC_IPV4_WEBSOCKET

export const OFFSET_REDIRECT_STATIC_IPV4_WEBSOCKET_PORT         = 12;
export const OFFSET_REDIRECT_STATIC_IPV4_WEBSOCKET_HOST         = 16;

// offsets for TYPE_COORDINATION_FORWARD_IPV4_UDP

export const OFFSET_REDIRECT_STATIC_IPV4_UDP_PORT               = 12;
export const OFFSET_REDIRECT_STATIC_IPV4_UDP_HOST               = 16;

// offsets for TYPE_COORDINATION_REDIRECT_STATIC_IPV6_WEBSOCKET

export const OFFSET_REDIRECT_STATIC_IPV6_WEBSOCKET_PORT         = 12;
export const OFFSET_REDIRECT_STATIC_IPV6_WEBSOCKET_HOST         = 16;

// offsets for TYPE_COORDINATION_REDIRECT_STATIC_IPV6_UDP

export const OFFSET_REDIRECT_STATIC_IPV6_UDP_PORT               = 12;
export const OFFSET_REDIRECT_STATIC_IPV6_UDP_HOST               = 16;

////////////////////////////////////////////////////////////////////////
// TYPES                                                              //
////////////////////////////////////////////////////////////////////////

// all defined types for coordination packets
export const TYPE_COORDINATION_FORWARD_IPV4_WEBSOCKET           = 0;
export const TYPE_COORDINATION_FORWARD_IPV4_UDP                 = 1;
export const TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET           = 2;
export const TYPE_COORDINATION_FORWARD_IPV6_UDP                 = 3;
export const TYPE_COORDINATION_REDIRECT_STATIC_IPV4_WEBSOCKET   = 4;
export const TYPE_COORDINATION_REDIRECT_STATIC_IPV4_UDP         = 5;
export const TYPE_COORDINATION_REDIRECT_STATIC_IPV6_WEBSOCKET   = 6;
export const TYPE_COORDINATION_REDIRECT_STATIC_IPV6_UDP         = 7;

export const TYPE_COORDINATION_ANNOUNCE_PEER_IPV4_WEBSOCKET     = 12;
export const TYPE_COORDINATION_ANNOUNCE_PEER_IPV4_UDP           = 13;
export const TYPE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET     = 14;
export const TYPE_COORDINATION_ANNOUNCE_PEER_IPV6_UDP           = 15;

export const REPLY_TYPE_IPV4_WEBSOCKET                          = 0;
export const REPLY_TYPE_IPV4_UDP                                = 1;
export const REPLY_TYPE_IPV6_WEBSOCKET                          = 2;
export const REPLY_TYPE_IPV6_UDP                                = 3;
