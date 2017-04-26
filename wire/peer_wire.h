#ifndef LIGHTNING_WIRE_PEER_WIRE_H
#define LIGHTNING_WIRE_PEER_WIRE_H
#include "config.h"
#include <stdbool.h>
#include <wire/gen_peer_wire.h>

/* BOLT #1:
 *
 * A node MUST ignore a received message of unknown type, if that type is odd.
 *
 * A node MUST fail the channels if it receives a message of unknown type, if
 * that type is even.
 */

/* Return true if it's an unknown message.  cursor is a tal ptr. */
bool unknown_msg(const u8 *cursor);
/* Return true if it's an unknown ODD message.  cursor is a tal ptr. */
bool unknown_msg_discardable(const u8 *cursor);

#endif /* LIGHTNING_WIRE_PEER_WIRE_H */
