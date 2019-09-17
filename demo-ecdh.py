#!/usr/bin/env python3
#*******************************************************************************
#*   Ledger Blue
#*   (c) 2016 Ledger
#*
#*  Licensed under the Apache License, Version 2.0 (the "License");
#*  you may not use this file except in compliance with the License.
#*  You may obtain a copy of the License at
#*
#*      http://www.apache.org/licenses/LICENSE-2.0
#*
#*  Unless required by applicable law or agreed to in writing, software
#*  distributed under the License is distributed on an "AS IS" BASIS,
#*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#*  See the License for the specific language governing permissions and
#*  limitations under the License.
#********************************************************************************
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
from secp256k1 import PublicKey
import bitcoin
import struct
from fastecdsa.encoding.sec1 import SEC1Encoder
from fastecdsa import curve

bipp44_path = (
               "8000002C"
              +"80000378"
              +"80000000"
              +"00000000"
              +"00000000")

b = bytes.fromhex("037edf1d72c29e6de321e95d1d0c2736223fe895009bf448e520c1333b05d6d6fd")
p = SEC1Encoder.decode_public_key(b, curve=curve.P256)
p2 = SEC1Encoder.encode_public_key(p, compressed=False).hex()

payload = bytes.fromhex(p2 + bipp44_path)

ecdhPayloadArray = [payload]

dongle = getDongle(True)
publicKey = dongle.exchange(bytes.fromhex("80040000FF"+ bipp44_path))
print("got publicKey " + publicKey.hex())
print("compressed: " + bitcoin.compress(publicKey).hex())
print("requesting ecdh with: " + p2)

for ecdhPayload in ecdhPayloadArray:
    try:
        offset = 0
        while offset < len(ecdhPayload):
            if (len(ecdhPayload) - offset) > 255:
                chunk = ecdhPayload[offset : offset + 255] 
            else:
                chunk = ecdhPayload[offset:]
            if (offset + len(chunk)) == len(ecdhPayload):
                p1 = b'\x80'
            else:
                p1 = b'\x00'
            apdu = bytes.fromhex("800a") + p1 + b'\x00' + struct.pack("B", len(chunk)) + chunk
            signature = dongle.exchange(apdu)
            offset += len(chunk)      
        print("shared secret: " + signature.hex())
    except CommException as comm:
        if comm.sw == 0x6985:
            print("Aborted by user")
        else:
            print("Invalid status ".format(comm.sw))

