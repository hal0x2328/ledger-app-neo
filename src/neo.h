/*
 * MIT License, see root folder for full license.
 */

#ifndef NEO_H
#define NEO_H

#include "os.h"
#include "cx.h"
#include <stdbool.h>
#include "os_io_seproxyhal.h"
#include "ui.h"

/** parse the raw transaction in raw_tx and fill up the screens in tx_desc. */
unsigned char display_tx_desc(void);

/** displays the "no public key" message, prior to a public key being requested. */
void display_no_public_key(void);

/** displays the public address */
void display_public_address(const unsigned char * public_key);

/** gets the public address */
void get_public_address(const unsigned char * public_key, char * address_base58 );

#endif // NEO_H
